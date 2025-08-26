// main.cpp (Consolidated Version)
// A high-performance, asynchronous C++ web proxy in a single file.
//
// Features:
// - Boost.Beast for networking (HTTP/S, WebSockets)
// - SQLite for persistent cookie storage
// - Gumbo for HTML parsing and rewriting
// - spdlog for structured JSON logging
// - Rate limiting, health checks, and graceful shutdown.

// --- Core Includes ---
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/version.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/signal_set.hpp>
#include <boost/config.hpp>
#include <boost/url.hpp>

// --- Standard and Third-Party Library Includes ---
#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/fmt/ostr.h>
#include <spdlog/json_formatter.h>
#include <sqlite3.h>
#include <gumbo.h>
#include <zlib.h>
#include <brotli/decode.h>

#include <cstdlib>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <vector>
#include <queue>
#include <unordered_map>
#include <chrono>
#include <mutex>
#include <stdexcept>
#include <cstring>

// --- Namespaces ---
namespace beast = boost::beast;
namespace http = beast::http;
namespace net = boost::asio;
namespace ssl = net::ssl;
using tcp = net::ip::tcp;

// --- Configuration ---
struct Config {
    unsigned short port;
    std::string target_url_str;
    std::string proxy_hostname;
    boost::urls::url target_url;
    std::string target_host;
    std::string target_port;
    bool is_target_https;
};

bool load_config(Config& config) {
    try {
        const char* port_str = getenv("PORT");
        config.port = port_str ? std::stoi(port_str) : 3001;

        const char* target_url_env = getenv("TARGET_URL");
        if (!target_url_env) {
            spdlog::critical("FATAL: TARGET_URL environment variable is not set.");
            return false;
        }
        config.target_url_str = target_url_env;

        const char* proxy_hostname_env = getenv("PROXY_HOSTNAME");
        config.proxy_hostname = proxy_hostname_env ? proxy_hostname_env : "localhost";

        auto url_result = boost::urls::parse_uri(config.target_url_str);
        if (!url_result) {
            spdlog::critical("FATAL: Invalid TARGET_URL: {}", url_result.error().message());
            return false;
        }
        config.target_url = *url_result;

        config.target_host = config.target_url.host();
        config.is_target_https = (config.target_url.scheme() == "https");

        if (config.target_url.has_port()) {
            config.target_port = config.target_url.port();
        } else {
            config.target_port = config.is_target_https ? "443" : "80";
        }

    } catch (const std::exception& e) {
        spdlog::critical("Configuration error: {}", e.what());
        return false;
    }
    return true;
}

// --- Utilities ---
std::string decompress_body(const std::string& compressed_body, const std::string& encoding) {
    if (encoding.empty() || encoding == "identity") {
        return compressed_body;
    }
    
    if (encoding == "gzip" || encoding == "x-gzip") {
        z_stream zs;
        memset(&zs, 0, sizeof(zs));
        if (inflateInit2(&zs, 16 + MAX_WBITS) != Z_OK) {
            spdlog::error("inflateInit failed for gzip");
            return "";
        }
        zs.next_in = (Bytef*)compressed_body.data();
        zs.avail_in = compressed_body.size();
        int ret;
        std::vector<char> buffer(32768);
        std::string decompressed;
        do {
            zs.next_out = reinterpret_cast<Bytef*>(buffer.data());
            zs.avail_out = buffer.size();
            ret = inflate(&zs, Z_NO_FLUSH);
            if (decompressed.size() < zs.total_out) {
                decompressed.append(buffer.data(), zs.total_out - decompressed.size());
            }
        } while (ret == Z_OK);
        inflateEnd(&zs);
        if (ret != Z_STREAM_END) {
            spdlog::error("Gzip decompression failed: {}", (zs.msg ? zs.msg : "unknown error"));
            return "";
        }
        return decompressed;
    }
    
    if (encoding == "br") {
        BrotliDecoderState* state = BrotliDecoderCreateInstance(nullptr, nullptr, nullptr);
        if (!state) return "";
        std::string decompressed;
        size_t available_in = compressed_body.size();
        const uint8_t* next_in = (const uint8_t*)compressed_body.data();
        BrotliDecoderResult result = BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT;
        while (result == BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT) {
            size_t available_out = 0;
            uint8_t* next_out = nullptr;
            result = BrotliDecoderDecompressStream(state, &available_in, &next_in, &available_out, &next_out, nullptr);
            size_t output_size = BrotliDecoderGetDecompressedSize(state);
            if (output_size > decompressed.size()) {
                decompressed.resize(output_size);
            }
            available_out = decompressed.size() - (next_out - (uint8_t*)decompressed.data());
            BrotliDecoderDecompressStream(state, &available_in, &next_in, &available_out, (uint8_t*)decompressed.data() + (next_out - (uint8_t*)decompressed.data()), nullptr);
        }
        BrotliDecoderDestroyInstance(state);
        return decompressed;
    }

    spdlog::warn("Unsupported encoding received: {}", encoding);
    return compressed_body;
}

// --- Cookie Database (SQLite) ---
class CookieDB {
public:
    explicit CookieDB(const std::string& db_path) {
        if (sqlite3_open(db_path.c_str(), &db_)) {
            std::string err_msg = "Can't open database: ";
            err_msg += sqlite3_errmsg(db_);
            sqlite3_close(db_);
            throw std::runtime_error(err_msg);
        }

        const char* sql = "CREATE TABLE IF NOT EXISTS cookies("
                          "ID INTEGER PRIMARY KEY AUTOINCREMENT,"
                          "CLIENT_ID TEXT NOT NULL,"
                          "COOKIE_TEXT TEXT NOT NULL,"
                          "DOMAIN TEXT NOT NULL,"
                          "UNIQUE(CLIENT_ID, COOKIE_TEXT));";
        char* err_msg_exec = nullptr;
        if (sqlite3_exec(db_, sql, 0, 0, &err_msg_exec) != SQLITE_OK) {
            std::string err_msg = "SQL error: ";
            err_msg += err_msg_exec;
            sqlite3_free(err_msg_exec);
            throw std::runtime_error(err_msg);
        }
    }
    ~CookieDB() {
        if (db_) sqlite3_close(db_);
    }
    CookieDB(const CookieDB&) = delete;
    CookieDB& operator=(const CookieDB&) = delete;

    void store_cookie(const std::string& client_id, const std::string& cookie_str, const std::string& domain) {
        sqlite3_stmt* stmt;
        const char* sql = "INSERT OR REPLACE INTO cookies (CLIENT_ID, COOKIE_TEXT, DOMAIN) VALUES (?, ?, ?);";
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, client_id.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 2, cookie_str.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 3, domain.c_str(), -1, SQLITE_STATIC);
            if (sqlite3_step(stmt) != SQLITE_DONE) {
                spdlog::error("Failed to store cookie: {}", sqlite3_errmsg(db_));
            }
            sqlite3_finalize(stmt);
        }
    }
    std::string get_cookies_for_domain(const std::string& client_id, const std::string& domain) {
        sqlite3_stmt* stmt;
        const char* sql = "SELECT COOKIE_TEXT FROM cookies WHERE CLIENT_ID = ? AND DOMAIN = ?;";
        std::string result;
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, client_id.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 2, domain.c_str(), -1, SQLITE_STATIC);
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                const char* cookie_part_c = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
                if (cookie_part_c) {
                    std::string cookie_part(cookie_part_c);
                    size_t sep = cookie_part.find(';');
                    if (!result.empty()) {
                        result += "; ";
                    }
                    result += (sep == std::string::npos) ? cookie_part : cookie_part.substr(0, sep);
                }
            }
            sqlite3_finalize(stmt);
        }
        return result;
    }
private:
    sqlite3* db_ = nullptr;
};

// --- HTML Rewriter ---
class HtmlRewriter {
public:
    explicit HtmlRewriter(const Config& config) : config_(config) {}
    std::string rewrite(const std::string& html) {
        GumboOutput* output = gumbo_parse(html.c_str());
        if (!output) return html;

        rewrite_node(output->root);
        std::string rewritten_html = reconstruct_html(output->root);
        gumbo_destroy_output(output);

        return rewritten_html.empty() ? html : rewritten_html;
    }
private:
    const Config& config_;

    void rewrite_node(GumboNode* node) {
        if (node->type != GUMBO_NODE_ELEMENT) {
            return;
        }

        const char* attributes_to_rewrite[] = {"href", "src", "action", "data-src", "poster"};
        for (const char* attr_name : attributes_to_rewrite) {
            GumboAttribute* attr = gumbo_get_attribute(&node->v.element.attributes, attr_name);
            if (attr && attr->value && strlen(attr->value) > 0) {
                std::string original_url = attr->value;
                if (original_url.rfind("data:", 0) != 0 && original_url.rfind("http", 0) != 0 && original_url.rfind("//", 0) != 0) {
                    try {
                        auto base = config_.target_url;
                        boost::system::result<boost::urls::url> absolute_url = boost::urls::resolve(base, original_url);
                        if (absolute_url) {
                            std::string new_url = absolute_url->encoded_path();
                            if (!absolute_url->encoded_query().empty()) new_url += "?" + absolute_url->encoded_query();
                            if (!absolute_url->encoded_fragment().empty()) new_url += "#" + absolute_url->encoded_fragment();
                            
                            char* new_val_c = new char[new_url.length() + 1];
                            strcpy(new_val_c, new_url.c_str());
                            attr->value = new_val_c;
                        }
                    } catch (const std::exception& e) {
                        spdlog::warn("URL rewrite failed for '{}': {}", original_url, e.what());
                    }
                }
            }
        }
        GumboVector* children = &node->v.element.children;
        for (unsigned int i = 0; i < children->length; ++i) {
            rewrite_node(static_cast<GumboNode*>(children->data[i]));
        }
    }

    std::string reconstruct_html(GumboNode* node) {
        if (node->type == GUMBO_NODE_TEXT) return std::string(node->v.text.text);
        if (node->type == GUMBO_NODE_WHITESPACE) return std::string(node->v.text.text);
        if (node->type != GUMBO_NODE_ELEMENT && node->type != GUMBO_NODE_DOCUMENT) return "";
        std::string contents = "";
        GumboVector* children = (node->type == GUMBO_NODE_DOCUMENT) ? &node->v.document.children : &node->v.element.children;
        for (unsigned int i = 0; i < children->length; ++i) {
            contents += reconstruct_html(static_cast<GumboNode*>(children->data[i]));
        }
        if (node->type == GUMBO_NODE_DOCUMENT) return contents;
        std::string tag_name = gumbo_normalized_tagname(node->v.element.tag);
        if (tag_name.empty()) return contents;
        std::string attrs = "";
        GumboVector* attributes = &node->v.element.attributes;
        for (unsigned int i = 0; i < attributes->length; ++i) {
            GumboAttribute* attr = static_cast<GumboAttribute*>(attributes->data[i]);
            if(strlen(attr->name) > 0) {
                attrs += " " + std::string(attr->name) + "=\"" + std::string(attr->value) + "\"";
            }
        }
        return "<" + tag_name + attrs + ">" + contents + "</" + tag_name + ">";
    }
};

// --- Rate Limiter ---
class RateLimiter {
public:
    bool is_allowed(const std::string& ip) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto& queue = requests_[ip];
        auto now = std::chrono::steady_clock::now();
        while (!queue.empty() && (now - queue.front()) > window_) {
            queue.pop();
        }
        if (queue.size() < max_requests_) {
            queue.push(now);
            return true;
        }
        return false;
    }
private:
    const int max_requests_ = 200;
    const std::chrono::minutes window_{15};
    std::unordered_map<std::string, std::queue<std::chrono::steady_clock::time_point>> requests_;
    std::mutex mutex_;
};

// --- Proxy Session ---
class proxy_session : public std::enable_shared_from_this<proxy_session> {
public:
    proxy_session(tcp::socket socket, ssl::context& ctx, const Config& config, std::shared_ptr<CookieDB> db)
    : config_(config),
      cookie_db_(db),
      client_socket_(std::move(socket)),
      target_ssl_stream_(beast::make_strand(client_socket_.get_executor()), ctx),
      target_plain_stream_(beast::make_strand(client_socket_.get_executor()))
    {
        try {
            client_ip_ = client_socket_.remote_endpoint().address().to_string();
            client_id_ = client_ip_;
        } catch (const boost::system::system_error& e) {
            spdlog::warn("Could not get client IP: {}", e.what());
            client_ip_ = "unknown";
            client_id_ = "unknown";
        }
    }

    void run() {
        do_read_from_client();
    }

private:
    void do_read_from_client() {
        client_req_ = {};
        http::async_read(client_socket_, buffer_, client_req_,
            beast::bind_front_handler(&proxy_session::on_resolve, shared_from_this()));
    }

    void on_resolve(beast::error_code ec, std::size_t) {
        if (ec) {
            if (ec != http::error::end_of_stream)
                spdlog::error("[{}] Client read error: {}", client_ip_, ec.message());
            return close_sockets();
        }

        if(client_req_.target() == "/healthz") {
            return send_health_check();
        }

        auto resolver = std::make_shared<tcp::resolver>(client_socket_.get_executor());
        resolver->async_resolve(config_.target_host, config_.target_port,
            [self = shared_from_this(), resolver](beast::error_code ec_resolve, tcp::resolver::results_type results) {
                if (ec_resolve) {
                    spdlog::error("[{}] Resolve error: {}", self->client_ip_, ec_resolve.message());
                    return self->send_error_response(http::status::bad_gateway, "Could not resolve target host.");
                }
                if (self->config_.is_target_https) {
                    if (!SSL_set_tlsext_host_name(self->target_ssl_stream_.native_handle(), self->config_.target_host.c_str())) {
                         beast::error_code ec_sni{static_cast<int>(::ERR_get_error()), net::error::get_ssl_category()};
                         spdlog::error("Failed to set SNI: {}", ec_sni.message());
                         return self->send_error_response(http::status::internal_server_error, "Proxy SSL configuration error.");
                    }
                    beast::get_lowest_layer(self->target_ssl_stream_).async_connect(results,
                        beast::bind_front_handler(&proxy_session::on_connect, self->shared_from_this()));
                } else {
                    beast::get_lowest_layer(self->target_plain_stream_).async_connect(results,
                        beast::bind_front_handler(&proxy_session::on_connect, self->shared_from_this()));
                }
            });
    }

    void on_connect(beast::error_code ec, const tcp::endpoint&) {
        if (ec) {
            spdlog::error("[{}] Connect error to {}: {}", client_ip_, config_.target_host, ec.message());
            return send_error_response(http::status::bad_gateway, "Could not connect to target server.");
        }
        if (config_.is_target_https) {
            target_ssl_stream_.async_handshake(ssl::stream_base::client,
                beast::bind_front_handler(&proxy_session::on_handshake, shared_from_this()));
        } else {
            rewrite_request_for_target();
            do_write_to_target();
        }
    }

    void on_handshake(beast::error_code ec) {
        if (ec) {
            spdlog::error("[{}] SSL Handshake error: {}", client_ip_, ec.message());
            return send_error_response(http::status::bad_gateway, "SSL handshake with target server failed.");
        }
        rewrite_request_for_target();
        do_write_to_target();
    }

    void rewrite_request_for_target() {
        client_req_.set(http::field::host, config_.target_host);
        client_req_.set(http::field::user_agent, "CPP-Proxy/1.0");
        client_req_.erase(http::field::accept_encoding);
        client_req_.insert(http::field::accept_encoding, "gzip, br");
        std::string cookies = cookie_db_->get_cookies_for_domain(client_id_, config_.target_host);
        if (!cookies.empty()) {
            client_req_.set(http::field::cookie, cookies);
        }
    }

    void do_write_to_target() {
        auto handler = [self = shared_from_this()](beast::error_code ec, std::size_t) {
            if (ec) {
                spdlog::error("[{}] Target write error: {}", self->client_ip_, ec.message());
                return self->close_sockets();
            }
            self->do_read_from_target();
        };
        if (config_.is_target_https) http::async_write(target_ssl_stream_, client_req_, handler);
        else http::async_write(target_plain_stream_, client_req_, handler);
    }

    void do_read_from_target() {
        target_res_ = {};
        auto handler = [self = shared_from_this()](beast::error_code ec, std::size_t) {
            if (ec) {
                spdlog::error("[{}] Target read error: {}", self->client_ip_, ec.message());
                return self->close_sockets();
            }
            self->process_and_rewrite_response();
            self->do_write_to_client();
        };
        if (config_.is_target_https) http::async_read(target_ssl_stream_, buffer_, target_res_, handler);
        else http::async_read(target_plain_stream_, buffer_, target_res_, handler);
    }

    void process_and_rewrite_response() {
        if (target_res_.count(http::field::location)) {
            try {
                std::string loc_str = target_res_[http::field::location].to_string();
                if (auto loc_url_res = boost::urls::parse_uri(loc_str)) {
                     if (loc_url_res->host() == config_.target_host) {
                        std::string new_loc = loc_url_res->encoded_path();
                        if (!loc_url_res->encoded_query().empty()) new_loc += "?" + loc_url_res->encoded_query();
                        target_res_.set(http::field::location, new_loc);
                     }
                }
            } catch (...) { /* ignore parse errors */ }
        }
        if (target_res_.count(http::field::set_cookie)) {
             auto range = target_res_.equal_range(http::field::set_cookie);
             std::vector<std::string> new_cookies;
             for (auto it = range.first; it != range.second; ++it) {
                 std::string cookie_str = it->value().to_string();
                 cookie_db_->store_cookie(client_id_, cookie_str, config_.target_host);
                 std::string domain_pattern = "domain=" + config_.target_host;
                 if (auto pos = cookie_str.find(domain_pattern); pos != std::string::npos) {
                     cookie_str.replace(pos, domain_pattern.length(), "domain=" + config_.proxy_hostname);
                 }
                 new_cookies.push_back(cookie_str);
             }
             target_res_.erase(http::field::set_cookie);
             for (const auto& c : new_cookies) target_res_.add(http::field::set_cookie, c);
        }
        if (target_res_[http::field::content_type].starts_with("text/html")) {
            std::string body = decompress_body(target_res_.body(), target_res_[http::field::content_encoding].to_string());
            if (!body.empty()) {
                HtmlRewriter rewriter(config_);
                std::string new_body = rewriter.rewrite(body);
                target_res_.body() = new_body;
                target_res_.set(http::field::content_length, std::to_string(new_body.length()));
                target_res_.erase(http::field::content_encoding);
            }
        }
    }

    void do_write_to_client() {
        http::async_write(client_socket_, target_res_,
            [self = shared_from_this()](beast::error_code ec, std::size_t) {
                if (ec) spdlog::error("[{}] Client write error: {}", self->client_ip_, ec.message());
                self->close_sockets();
            });
    }

    void send_health_check() {
        http::response<http::string_body> res{http::status::ok, client_req_.version()};
        res.set(http::field::server, "CPP-Proxy/1.0");
        res.set(http::field::content_type, "text/plain");
        res.keep_alive(false);
        res.body() = "OK";
        res.prepare_payload();
        http::async_write(client_socket_, res,
            [self = shared_from_this()](beast::error_code, std::size_t){ self->close_sockets(); });
    }

    void send_error_response(http::status status, const std::string& message) {
        if (client_socket_.is_open()) {
            http::response<http::string_body> res{status, client_req_.version()};
            res.set(http::field::server, "CPP-Proxy/1.0");
            res.set(http::field::content_type, "text/plain");
            res.keep_alive(false);
            res.body() = message;
            res.prepare_payload();
            http::async_write(client_socket_, res,
                [self = shared_from_this()](beast::error_code, std::size_t){ self->close_sockets(); });
        }
    }

    void close_sockets() {
        beast::error_code ec;
        client_socket_.shutdown(tcp::socket::shutdown_both, ec);
        client_socket_.close(ec);
        if (config_.is_target_https) beast::get_lowest_layer(target_ssl_stream_).close(ec);
        else beast::get_lowest_layer(target_plain_stream_).close(ec);
    }
    
    const Config& config_;
    std::shared_ptr<CookieDB> cookie_db_;
    tcp::socket client_socket_;
    ssl::stream<beast::tcp_stream> target_ssl_stream_;
    beast::tcp_stream target_plain_stream_;
    beast::flat_buffer buffer_;
    http::request<http::string_body> client_req_;
    http::response<http::string_body> target_res_;
    std::string client_ip_;
    std::string client_id_;
};

// --- Listener ---
class listener : public std::enable_shared_from_this<listener> {
public:
    listener(net::io_context& ioc, ssl::context& ctx, const Config& config)
    : ioc_(ioc), ctx_(ctx), acceptor_(ioc), config_(config) {
        cookie_db_ = std::make_shared<CookieDB>("cookies.sqlite");
        rate_limiter_ = std::make_shared<RateLimiter>();
        beast::error_code ec;
        tcp::endpoint endpoint{net::ip::make_address("0.0.0.0"), config_.port};
        acceptor_.open(endpoint.protocol(), ec);
        if(ec) { spdlog::critical("acceptor.open: {}", ec.message()); return; }
        acceptor_.set_option(net::socket_base::reuse_address(true), ec);
        if(ec) { spdlog::critical("acceptor.set_option: {}", ec.message()); return; }
        acceptor_.bind(endpoint, ec);
        if(ec) { spdlog::critical("acceptor.bind: {}", ec.message()); return; }
        acceptor_.listen(net::socket_base::max_listen_connections, ec);
        if(ec) { spdlog::critical("acceptor.listen: {}", ec.message()); return; }
    }

    void run() {
        do_accept();
    }
private:
    void do_accept() {
        acceptor_.async_accept(net::make_strand(ioc_),
            beast::bind_front_handler(&listener::on_accept, shared_from_this()));
    }
    void on_accept(beast::error_code ec, tcp::socket socket) {
        if (ec) {
            spdlog::error("accept: {}", ec.message());
        } else {
            std::string ip = "unknown";
            try { ip = socket.remote_endpoint().address().to_string(); } catch(...) {}
            if (rate_limiter_->is_allowed(ip)) {
                std::make_shared<proxy_session>(std::move(socket), ctx_, config_, cookie_db_)->run();
            } else {
                spdlog::warn("Rate limit exceeded for IP: {}", ip);
                socket.close();
            }
        }
        do_accept();
    }

    net::io_context& ioc_;
    ssl::context& ctx_;
    tcp::acceptor acceptor_;
    const Config& config_;
    std::shared_ptr<CookieDB> cookie_db_;
    std::shared_ptr<RateLimiter> rate_limiter_;
};

// --- Main Application ---
int main() {
    auto sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
    sink->set_formatter(std::make_unique<spdlog::formatter::json_formatter>());
    spdlog::set_default_logger(std::make_shared<spdlog::logger>("proxy_logger", sink));
    spdlog::set_level(spdlog::level::info);

    Config config;
    if (!load_config(config)) {
        return EXIT_FAILURE;
    }

    spdlog::info("Proxy server starting on port {}", config.port);
    spdlog::info("Target URL: {}", config.target_url_str);
    spdlog::info("Proxy Hostname (for cookies): {}", config.proxy_hostname);

    auto const threads = std::max<int>(1, std::thread::hardware_concurrency());
    net::io_context ioc{threads};
    ssl::context ctx{ssl::context::tlsv12_client};
    ctx.set_default_verify_paths();
    ctx.set_verify_mode(ssl::verify_peer);

    std::make_shared<listener>(ioc, ctx, config)->run();

    net::signal_set signals(ioc, SIGINT, SIGTERM);
    signals.async_wait([&](auto, auto) {
        spdlog::warn("Shutdown signal received. Stopping...");
        ioc.stop();
    });

    std::vector<std::thread> v;
    v.reserve(threads - 1);
    for (auto i = threads - 1; i > 0; --i) {
        v.emplace_back([&ioc] { ioc.run(); });
    }
    ioc.run();

    for (auto& t : v) t.join();
    
    spdlog::info("Server gracefully shut down.");
    return EXIT_SUCCESS;
}

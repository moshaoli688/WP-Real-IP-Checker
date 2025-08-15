<?php
/*
Plugin Name: WP Real IP Checker
Plugin URI:   https://github.com/moshaoli688/WP-Real-IP-Checker/
Description:  获取反向代理/CDN（如 Cloudflare、Nginx）后的真实客户端 IP。支持可信代理 CIDR 白名单、可选安全模式与 Cloudflare 网段自动同步（含定时任务）。
Version:      1.7.0
Author:       墨少
Author URI:   https://www.msl.la
Text Domain:  wp-real-ip-checker
Domain Path:  /languages
Requires at least: 5.2
Requires PHP:      7.4
License:      AGPLv3 or later
License URI:  https://www.gnu.org/licenses/agpl-3.0.html
*/


if (!defined('ABSPATH')) exit;

/** ========= 基础工具 ========= */

if (!function_exists('ric_is_cli')) {
    function ric_is_cli() {
        return (php_sapi_name() === 'cli' || defined('WP_CLI'));
    }
}

if (!function_exists('ric_is_public_ip')) {
    function ric_is_public_ip($ip) {
        if (!filter_var($ip, FILTER_VALIDATE_IP)) return false;
        $flags = FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE;
        return (bool) filter_var($ip, FILTER_VALIDATE_IP, $flags);
    }
}

if (!function_exists('ric_ip_in_cidrs')) {
    function ric_ip_in_cidrs($ip, array $cidrs) {
        if (!filter_var($ip, FILTER_VALIDATE_IP)) return false;
        $ip_bin = @inet_pton($ip);
        if ($ip_bin === false) return false;

        foreach ($cidrs as $cidr) {
            $cidr = trim($cidr);
            if ($cidr === '') continue;

            if (strpos($cidr, '/') === false) {
                $cidr .= (strpos($cidr, ':') !== false) ? '/128' : '/32';
            }
            list($subnet, $mask) = explode('/', $cidr, 2);
            if (!filter_var($subnet, FILTER_VALIDATE_IP)) continue;

            $subnet_bin = @inet_pton($subnet);
            if ($subnet_bin === false) continue;
            $mask = (int) $mask;

            $bytes = intdiv($mask, 8);
            $bits  = $mask % 8;

            if (strncmp($ip_bin, $subnet_bin, $bytes) !== 0) continue;
            if ($bits === 0) return true;

            $ip_byte     = ord($ip_bin[$bytes]);
            $subnet_byte = ord($subnet_bin[$bytes]);
            $mask_byte   = ~((1 << (8 - $bits)) - 1) & 0xFF;

            if (($ip_byte & $mask_byte) === ($subnet_byte & $mask_byte)) return true;
        }
        return false;
    }
}

/** ========= 设置项（Options）与默认值 ========= */

const RIC_OPT_KEY      = 'ric_settings';
const RIC_CF_CACHE_KEY = 'ric_cf_cidrs_cache';

function ric_default_settings() {
    return [
        'require_trusted_proxy' => 1,    // 默认安全：仅信任可信代理来源的头
        'include_cloudflare'    => 0,    // 是否自动包含 Cloudflare 官方网段
        'trusted_proxies'       => "",   // 自定义 CIDR/单 IP（每行一个）
        'show_admin_footer'     => 1,    // 后台页脚显示当前 IP（仅管理员）
    ];
}

function ric_get_settings() {
    $opts = get_option(RIC_OPT_KEY, []);
    return wp_parse_args($opts, ric_default_settings());
}

/** ========= Cloudflare 网段获取与缓存 ========= */

function ric_fetch_cloudflare_cidrs() {
    // 缓存 24 小时
    $cached = get_transient(RIC_CF_CACHE_KEY);
    if (is_array($cached) && isset($cached['cidrs']) && is_array($cached['cidrs'])) {
        return $cached['cidrs'];
    }

    $cidrs = [];
    $urls = [
        'https://www.cloudflare.com/ips-v4',
        'https://www.cloudflare.com/ips-v6',
    ];

    foreach ($urls as $url) {
        $resp = wp_remote_get($url, ['timeout' => 8, 'user-agent' => 'WP Real IP Checker/1.7.0']);
        if (is_wp_error($resp)) continue;
        $code = wp_remote_retrieve_response_code($resp);
        if ($code !== 200) continue;
        $body = wp_remote_retrieve_body($resp);
        foreach (preg_split('/\r\n|\r|\n/', $body) as $line) {
            $line = trim($line);
            if ($line !== '') $cidrs[] = $line;
        }
    }

    $cidrs = array_values(array_unique($cidrs));
    if ($cidrs) {
        set_transient(RIC_CF_CACHE_KEY, ['cidrs' => $cidrs], DAY_IN_SECONDS);
    }
    return $cidrs;
}

/** ========= 可信代理列表与可检查头 ========= */

function ric_get_trusted_proxies() {
    static $cache = null;
    if ($cache !== null) return $cache;

    $s = ric_get_settings();
    $trusted = [];

    if (!empty($s['trusted_proxies'])) {
        $lines = preg_split('/\r\n|\r|\n/', $s['trusted_proxies']);
        foreach ($lines as $line) {
            $line = trim($line);
            if ($line !== '') $trusted[] = $line;
        }
    }

    if (!empty($s['include_cloudflare'])) {
        $cf = ric_fetch_cloudflare_cidrs();
        if ($cf) $trusted = array_merge($trusted, $cf);
    }

    $trusted = apply_filters('real_ip_checker_trusted_proxies', $trusted);
    $cache = array_values(array_unique(array_map('trim', $trusted)));
    return $cache;
}

/** ========= 核心解析：获取真实 IP ========= */

function ric_get_real_ip() {
    static $cached = null;
    if ($cached !== null) return $cached;

    $remote = $_SERVER['REMOTE_ADDR'] ?? '';
    if (!filter_var($remote, FILTER_VALIDATE_IP)) {
        return $cached = '127.0.0.1';
    }

    $s = ric_get_settings();
    $require_trusted = !empty($s['require_trusted_proxy']);
    $trusted = ric_get_trusted_proxies();
    $from_trusted_proxy = $trusted ? ric_ip_in_cidrs($remote, $trusted) : false;

    // 如果要求可信代理且不在可信列表 → 直接 REMOTE_ADDR
    if ($require_trusted && !$from_trusted_proxy) {
        return $cached = $remote;
    }

    // 是否 Cloudflare 来源
    $cf_ranges = $s['include_cloudflare'] ? ric_fetch_cloudflare_cidrs() : [];
    $from_cf = $cf_ranges ? ric_ip_in_cidrs($remote, $cf_ranges) : false;

    if ($from_cf) {
        // 优先 Cloudflare 专用头
        if (!empty($_SERVER['HTTP_CF_CONNECTING_IP']) && ric_is_public_ip($_SERVER['HTTP_CF_CONNECTING_IP'])) {
            return $cached = trim($_SERVER['HTTP_CF_CONNECTING_IP']);
        }
        if (!empty($_SERVER['HTTP_TRUE_CLIENT_IP']) && ric_is_public_ip($_SERVER['HTTP_TRUE_CLIENT_IP'])) {
            return $cached = trim($_SERVER['HTTP_TRUE_CLIENT_IP']);
        }
        // 都没有就回退 REMOTE_ADDR
        return $cached = $remote;
    }
    $headers = apply_filters('real_ip_checker_headers_non_cf', [
      'HTTP_X_FORWARDED_FOR',
      'HTTP_X_REAL_IP',
      'HTTP_CLIENT_IP',
      'HTTP_X_FORWARDED',
      'HTTP_FORWARDED_FOR',
      'HTTP_FORWARDED',
    ]);

    // 其他可信代理来源 → 按常规头列表找
    foreach ($headers as $header) {
        if (empty($_SERVER[$header])) continue;
        if ($header === 'HTTP_X_FORWARDED_FOR') {
            foreach (explode(',', $_SERVER[$header]) as $ip) {
                $ip = trim($ip);
                if (ric_is_public_ip($ip)) return $cached = $ip;
            }
            continue;
        }
        if (ric_is_public_ip(trim($_SERVER[$header]))) {
            return $cached = trim($_SERVER[$header]);
        }
    }

    return $cached = $remote;
}

/** ========= 初始化时覆盖 REMOTE_ADDR（仅 Web 环境） ========= */

function ric_update_remote_addr() {
    if (ric_is_cli()) return;
    $real = ric_get_real_ip();
    if (filter_var($real, FILTER_VALIDATE_IP)) {
        $_SERVER['REMOTE_ADDR'] = $real;
    }
}
add_action('init', 'ric_update_remote_addr', 0);

/** ========= 后台页脚显示（仅管理员） ========= */

function ric_show_ip_in_admin_footer() {
    $s = ric_get_settings();
    if (empty($s['show_admin_footer'])) return;
    if (!current_user_can('manage_options')) return;

    $ip = esc_html(ric_get_real_ip());
    echo '<p style="text-align:center;font-size:12px;margin-top:10px;">Your IP: ' . $ip . '</p>';
}
add_action('admin_footer', 'ric_show_ip_in_admin_footer');

/** ========= 前台短代码 ========= */

function ric_shortcode_real_ip() {
    return esc_html(ric_get_real_ip());
}
add_shortcode('real_ip', 'ric_shortcode_real_ip');

/** ========= 设置页（Settings → WP Real IP Checker） ========= */

function ric_register_settings() {
    register_setting(
        'ric_settings_group',
        RIC_OPT_KEY,
        [
            'type'              => 'array',
            'sanitize_callback' => 'ric_sanitize_settings',
            'default'           => ric_default_settings(),
        ]
    );

    add_settings_section(
        'ric_main_section',
        __('WP Real IP Checker Settings', 'wp-real-ip-checker'),
        function () {
            echo '<p>'.esc_html__('根据你的部署环境调整安全/兼容性和可信代理列表。', 'wp-real-ip-checker').'</p>';
        },
        'ric_settings_page'
    );

    add_settings_field(
        'require_trusted_proxy',
        __('只信任可信代理的头部（安全模式）', 'wp-real-ip-checker'),
        'ric_field_require_trusted_proxy',
        'ric_settings_page',
        'ric_main_section'
    );

    add_settings_field(
        'include_cloudflare',
        __('自动包含 Cloudflare 官方网段', 'wp-real-ip-checker'),
        'ric_field_include_cloudflare',
        'ric_settings_page',
        'ric_main_section'
    );

    add_settings_field(
        'trusted_proxies',
        __('自定义可信代理（每行一个 CIDR 或 IP）', 'wp-real-ip-checker'),
        'ric_field_trusted_proxies',
        'ric_settings_page',
        'ric_main_section'
    );

    add_settings_field(
        'show_admin_footer',
        __('后台页脚显示当前 IP（仅管理员）', 'wp-real-ip-checker'),
        'ric_field_show_admin_footer',
        'ric_settings_page',
        'ric_main_section'
    );
}
add_action('admin_init', 'ric_register_settings');

function ric_sanitize_settings($input) {
    $defaults = ric_default_settings();
    $out = [
        'require_trusted_proxy' => empty($input['require_trusted_proxy']) ? 0 : 1,
        'include_cloudflare'    => empty($input['include_cloudflare']) ? 0 : 1,
        'trusted_proxies'       => isset($input['trusted_proxies']) ? sanitize_textarea_field($input['trusted_proxies']) : '',
        'show_admin_footer'     => empty($input['show_admin_footer']) ? 0 : 1,
    ];
    return wp_parse_args($out, $defaults);
}

function ric_field_require_trusted_proxy() {
    $s = ric_get_settings();
    echo '<label><input type="checkbox" name="'.esc_attr(RIC_OPT_KEY).'[require_trusted_proxy]" value="1" '.checked(1, $s['require_trusted_proxy'], false).' /> ';
    echo esc_html__('开启后只有当请求来自可信代理 CIDR 时才会解析 X-Forwarded-For 等头（推荐用于生产环境）。', 'wp-real-ip-checker');
    echo '</label>';
}

function ric_field_include_cloudflare() {
    $s = ric_get_settings();
    echo '<label><input type="checkbox" name="'.esc_attr(RIC_OPT_KEY).'[include_cloudflare]" value="1" '.checked(1, $s['include_cloudflare'], false).' /> ';
    echo esc_html__('自动拉取 Cloudflare 官方网段（每日缓存）。', 'wp-real-ip-checker');
    echo '</label> ';
    submit_button(__('立即同步 Cloudflare 网段', 'wp-real-ip-checker'), 'secondary', 'ric_sync_cf_now', false);
}

function ric_field_trusted_proxies() {
    $s = ric_get_settings();
    echo '<textarea name="'.esc_attr(RIC_OPT_KEY).'[trusted_proxies]" rows="6" cols="60" class="large-text code" placeholder="203.0.113.10/32&#10;203.0.113.0/24&#10;2001:db8::/32">'.esc_textarea($s['trusted_proxies']).'</textarea>';
    echo '<p class="description">'.esc_html__('支持 IPv4/IPv6，CIDR 或单 IP；每行一个。可与 Cloudflare 网段叠加。', 'wp-real-ip-checker').'</p>';
}

function ric_field_show_admin_footer() {
    $s = ric_get_settings();
    echo '<label><input type="checkbox" name="'.esc_attr(RIC_OPT_KEY).'[show_admin_footer]" value="1" '.checked(1, $s['show_admin_footer'], false).' /> ';
    echo esc_html__('在后台页脚显示当前解析到的 IP（仅管理员可见）。', 'wp-real-ip-checker');
    echo '</label>';
}

function ric_add_settings_page() {
    add_options_page(
        __('WP Real IP Checker', 'wp-real-ip-checker'),
        __('WP Real IP Checker', 'wp-real-ip-checker'),
        'manage_options',
        'ric_settings_page',
        'ric_render_settings_page'
    );
}
add_action('admin_menu', 'ric_add_settings_page');

function ric_render_settings_page() {
    if (!current_user_can('manage_options')) return;
    echo '<div class="wrap"><h1>'.esc_html__('WP Real IP Checker', 'wp-real-ip-checker').'</h1>';
    settings_errors('ric_messages');
    echo '<form method="post" action="options.php">';
    // 生成正确的 option_page/_wpnonce/_wp_http_referer
    settings_fields('ric_settings_group');
    do_settings_sections('ric_settings_page');
    submit_button();
    echo '</form></div>';
}

/** ========= 手动“立即同步”处理（在 admin_init 阶段） ========= */

add_action('admin_init', 'ric_handle_cf_sync');
function ric_handle_cf_sync() {
    if (empty($_POST['ric_sync_cf_now'])) return;
    if (!current_user_can('manage_options')) return;

    // 使用 settings_fields('ric_settings_group') 生成的 nonce（action: ric_settings_group-options）
    if (!check_admin_referer('ric_settings_group-options')) {
        add_settings_error('ric_messages', 'ric_cf_nonce', __('安全校验失败，请重试。', 'wp-real-ip-checker'), 'error');
        return;
    }

    delete_transient(RIC_CF_CACHE_KEY);
    $cidrs = ric_fetch_cloudflare_cidrs();

    if ($cidrs) {
        add_settings_error('ric_messages', 'ric_cf_ok', __('Cloudflare 网段已更新。', 'wp-real-ip-checker'), 'updated');
    } else {
        add_settings_error('ric_messages', 'ric_cf_fail', __('同步失败，已保持现有缓存或空列表。', 'wp-real-ip-checker'), 'error');
    }
}

/** ========= 设置保存后：首次开启“自动包含 CF”时立即预热 ========= */
add_action('update_option_' . RIC_OPT_KEY, 'ric_after_settings_update', 10, 2);
function ric_after_settings_update($old, $new) {
    $old_enabled = !empty($old['include_cloudflare']);
    $new_enabled = !empty($new['include_cloudflare']);
    if ($new_enabled && !$old_enabled) {
        delete_transient(RIC_CF_CACHE_KEY);
        ric_fetch_cloudflare_cidrs();
        add_settings_error('ric_messages', 'ric_cf_warm', __('已预热 Cloudflare 网段缓存。', 'wp-real-ip-checker'), 'updated');
    }
}

/** ========= 定时任务：每日刷新 Cloudflare 网段 ========= */

// 回调
add_action('ric_cron_refresh_cf', 'ric_cron_refresh_cf_cb');
function ric_cron_refresh_cf_cb() {
    $s = ric_get_settings();
    if (empty($s['include_cloudflare'])) return;
    delete_transient(RIC_CF_CACHE_KEY);
    ric_fetch_cloudflare_cidrs(); // 写回 transient
}

// 激活时安排；停用时清理
register_activation_hook(__FILE__, 'ric_activate_schedule');
function ric_activate_schedule() {
    if (!wp_next_scheduled('ric_cron_refresh_cf')) {
        $start = time() + rand(300, 1800); // 5~30 分钟随机延迟，避免同一时间拥堵
        wp_schedule_event($start, 'daily', 'ric_cron_refresh_cf');
    }
}
register_deactivation_hook(__FILE__, 'ric_deactivate_schedule');
function ric_deactivate_schedule() {
    wp_clear_scheduled_hook('ric_cron_refresh_cf');
}

/** ========= 卸载清理 ========= */
register_uninstall_hook(__FILE__, 'ric_uninstall');
function ric_uninstall() {
    delete_option(RIC_OPT_KEY);
    delete_transient(RIC_CF_CACHE_KEY);
    wp_clear_scheduled_hook('ric_cron_refresh_cf');
}

/** ========= 可选：调试信息（WP_DEBUG 时，仅管理员后台） ========= */
function ric_debug_info() {
    if (!defined('WP_DEBUG') || !WP_DEBUG) return;
    if (!current_user_can('manage_options')) return;

    $remote  = $_SERVER['REMOTE_ADDR'] ?? '';
    $trusted = ric_get_trusted_proxies();
    $from_trusted = $trusted ? ric_ip_in_cidrs($remote, $trusted) : false;

    $cf_cache = get_transient(RIC_CF_CACHE_KEY);
    $cf_count = (is_array($cf_cache) && !empty($cf_cache['cidrs']) && is_array($cf_cache['cidrs'])) ? count($cf_cache['cidrs']) : 0;

    $data = [
        'remote_addr'        => $remote,
        'from_trusted_proxy' => $from_trusted ? 'yes' : 'no',
        'resolved_real_ip'   => ric_get_real_ip(),
        'require_trusted'    => (int) ric_get_settings()['require_trusted_proxy'],
        'cf_transient_size'  => $cf_count,
    ];
    echo '<pre style="font-size:11px;opacity:.7">'. esc_html(print_r($data, true)) .'</pre>';
}

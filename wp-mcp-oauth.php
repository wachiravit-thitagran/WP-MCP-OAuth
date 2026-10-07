<?php
/**
 * Plugin Name: WP MCP OAuth
 * Plugin URI: https://github.com/wachiravit-thitagran/WP-MCP-OAuth
 * Description: OAuth 2.1 authorization layer for WordPress MCP endpoints, including PKCE, bearer authentication, and WordPress user mapping.
 * Version: 0.1.0
 * Requires at least: 6.9
 * Requires PHP: 7.4
 * Author: Wachiravit Thitagran
 * License: GPL-2.0-or-later
 * Text Domain: wp-mcp-oauth
 *
 * @package WP_MCP_OAuth
 */

defined( 'ABSPATH' ) || exit;

define( 'WP_MCP_OAUTH_VERSION', '0.1.0' );
define( 'WP_MCP_OAUTH_FILE', __FILE__ );
define( 'WP_MCP_OAUTH_DIR', plugin_dir_path( __FILE__ ) );

require_once WP_MCP_OAUTH_DIR . 'includes/class-database.php';
require_once WP_MCP_OAUTH_DIR . 'includes/class-server.php';
require_once WP_MCP_OAUTH_DIR . 'includes/class-bearer-auth.php';

/**
 * Activate plugin database tables.
 *
 * @return void
 */
function wp_mcp_oauth_activate() {
	\WP_MCP_OAuth\Database::install();
}
register_activation_hook( __FILE__, 'wp_mcp_oauth_activate' );

/**
 * Boot OAuth server and bearer authentication.
 *
 * @return void
 */
function wp_mcp_oauth_boot() {
	\WP_MCP_OAuth\Bearer_Auth::instance()->boot();
	\WP_MCP_OAuth\Server::instance()->boot();
}
add_action( 'plugins_loaded', 'wp_mcp_oauth_boot' );

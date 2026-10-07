<?php
/**
 * OAuth persistence.
 *
 * @package WP_MCP_OAuth
 */

namespace WP_MCP_OAuth;

defined( 'ABSPATH' ) || exit;

/**
 * Database helpers for authorization codes and tokens.
 */
final class Database {

	/**
	 * Install database tables.
	 *
	 * @return void
	 */
	public static function install() {
		global $wpdb;

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';

		$charset = $wpdb->get_charset_collate();
		$codes   = self::codes_table();
		$tokens  = self::tokens_table();

		dbDelta(
			"CREATE TABLE {$codes} (
				id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
				code_hash char(64) NOT NULL,
				user_id bigint(20) unsigned NOT NULL,
				client_id text NOT NULL,
				redirect_uri text NOT NULL,
				resource text NOT NULL,
				scope text NOT NULL,
				code_challenge varchar(128) NOT NULL,
				code_challenge_method varchar(16) NOT NULL,
				expires_at datetime NOT NULL,
				used_at datetime NULL,
				created_at datetime NOT NULL,
				PRIMARY KEY  (id),
				UNIQUE KEY code_hash (code_hash),
				KEY user_id (user_id)
			) {$charset};"
		);

		dbDelta(
			"CREATE TABLE {$tokens} (
				id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
				token_hash char(64) NOT NULL,
				token_type varchar(16) NOT NULL,
				user_id bigint(20) unsigned NOT NULL,
				client_id text NOT NULL,
				resource text NOT NULL,
				scope text NOT NULL,
				expires_at datetime NOT NULL,
				revoked_at datetime NULL,
				parent_id bigint(20) unsigned NULL,
				created_at datetime NOT NULL,
				PRIMARY KEY  (id),
				UNIQUE KEY token_hash (token_hash),
				KEY user_id (user_id),
				KEY token_type (token_type),
				KEY parent_id (parent_id)
			) {$charset};"
		);

		update_option( 'wp_mcp_oauth_db_version', WP_MCP_OAUTH_VERSION, false );
	}

	/**
	 * Codes table.
	 *
	 * @return string
	 */
	public static function codes_table() {
		global $wpdb;
		return $wpdb->prefix . 'mcp_oauth_codes';
	}

	/**
	 * Tokens table.
	 *
	 * @return string
	 */
	public static function tokens_table() {
		global $wpdb;
		return $wpdb->prefix . 'mcp_oauth_tokens';
	}

	/**
	 * Hash a secret for storage.
	 *
	 * @param string $value Secret.
	 * @return string
	 */
	public static function hash_secret( $value ) {
		return hash( 'sha256', $value );
	}

	/**
	 * Current GMT SQL datetime.
	 *
	 * @return string
	 */
	public static function now() {
		return gmdate( 'Y-m-d H:i:s' );
	}

	/**
	 * Future GMT SQL datetime.
	 *
	 * @param int $seconds Seconds from now.
	 * @return string
	 */
	public static function future( $seconds ) {
		return gmdate( 'Y-m-d H:i:s', time() + (int) $seconds );
	}
}

<?php
/**
 * Bearer-token authentication.
 *
 * @package WP_MCP_OAuth
 */

namespace WP_MCP_OAuth;

defined( 'ABSPATH' ) || exit;

/**
 * Maps OAuth bearer tokens to WordPress users.
 */
final class Bearer_Auth {

	/**
	 * Singleton.
	 *
	 * @var self|null
	 */
	private static $instance = null;

	/**
	 * Current token row.
	 *
	 * @var object|null
	 */
	private $token = null;

	/**
	 * Get singleton.
	 *
	 * @return self
	 */
	public static function instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}

		return self::$instance;
	}

	/**
	 * Register hooks.
	 *
	 * @return void
	 */
	public function boot() {
		add_filter( 'determine_current_user', array( $this, 'determine_current_user' ), 5 );
	}

	/**
	 * Resolve WordPress user from Bearer token.
	 *
	 * @param int|false $user_id Current user.
	 * @return int|false
	 */
	public function determine_current_user( $user_id ) {
		if ( $user_id ) {
			return $user_id;
		}

		$token = $this->bearer_token();

		if ( '' === $token ) {
			return $user_id;
		}

		$row = $this->find_access_token( $token );

		if ( ! $row ) {
			return $user_id;
		}

		$this->token = $row;

		return (int) $row->user_id;
	}

	/**
	 * Check whether current bearer token grants a scope.
	 *
	 * @param string $scope Scope.
	 * @return bool
	 */
	public function has_scope( $scope ) {
		if ( ! $this->token ) {
			return false;
		}

		$scopes = preg_split( '/\s+/', trim( (string) $this->token->scope ) );

		return in_array( $scope, $scopes, true );
	}

	/**
	 * Return authenticated token row.
	 *
	 * @return object|null
	 */
	public function current_token() {
		return $this->token;
	}

	/**
	 * Read bearer token from Authorization header.
	 *
	 * @return string
	 */
	private function bearer_token() {
		$header = '';

		if ( isset( $_SERVER['HTTP_AUTHORIZATION'] ) ) {
			$header = sanitize_text_field( wp_unslash( $_SERVER['HTTP_AUTHORIZATION'] ) );
		} elseif ( function_exists( 'getallheaders' ) ) {
			$headers = getallheaders();
			$header  = isset( $headers['Authorization'] ) ? (string) $headers['Authorization'] : '';
		}

		if ( ! preg_match( '/^Bearer\s+(.+)$/i', $header, $matches ) ) {
			return '';
		}

		return trim( $matches[1] );
	}

	/**
	 * Find valid access token.
	 *
	 * @param string $token Token.
	 * @return object|null
	 */
	private function find_access_token( $token ) {
		global $wpdb;

		$table = Database::tokens_table();
		$hash  = Database::hash_secret( $token );
		$now   = Database::now();

		$row = $wpdb->get_row(
			$wpdb->prepare(
				"SELECT * FROM {$table}
				WHERE token_hash = %s
				AND token_type = 'access'
				AND revoked_at IS NULL
				AND expires_at > %s
				LIMIT 1",
				$hash,
				$now
			)
		);

		if ( ! $row ) {
			return null;
		}

		if ( (string) $row->resource !== Server::resource_url() ) {
			return null;
		}

		return $row;
	}
}

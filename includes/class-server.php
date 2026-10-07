<?php
/**
 * OAuth 2.1 authorization server for the WordPress MCP endpoint.
 *
 * @package WP_MCP_OAuth
 */

namespace WP_MCP_OAuth;

defined( 'ABSPATH' ) || exit;

/**
 * OAuth server.
 */
final class Server {

	const ACCESS_TTL  = 3600;
	const REFRESH_TTL = 2592000;

	/**
	 * Singleton.
	 *
	 * @var self|null
	 */
	private static $instance = null;

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
	 * Boot routes.
	 *
	 * @return void
	 */
	public function boot() {
		add_action( 'parse_request', array( $this, 'route_request' ), 1 );
		add_filter( 'rest_authentication_errors', array( $this, 'protect_mcp_rest_endpoint' ), 99 );
	}

	/**
	 * OAuth issuer.
	 *
	 * @return string
	 */
	public static function issuer() {
		return untrailingslashit( home_url( '/' ) );
	}

	/**
	 * MCP resource URL.
	 *
	 * @return string
	 */
	public static function resource_url() {
		return rest_url( 'mcp/mcp-adapter-default-server' );
	}

	/**
	 * Supported scopes.
	 *
	 * @return string[]
	 */
	public static function scopes() {
		return array( 'wordpress:read', 'wordpress:write', 'wordpress:admin' );
	}

	/**
	 * Serve root OAuth routes.
	 *
	 * @return void
	 */
	public function route_request() {
		$path = wp_parse_url( isset( $_SERVER['REQUEST_URI'] ) ? wp_unslash( $_SERVER['REQUEST_URI'] ) : '/', PHP_URL_PATH );
		$path = '/' . ltrim( (string) $path, '/' );

		switch ( untrailingslashit( $path ) ) {
			case '/.well-known/oauth-protected-resource':
				$this->protected_resource_metadata();
				break;
			case '/.well-known/oauth-authorization-server':
				$this->authorization_server_metadata();
				break;
			case '/oauth/authorize':
				$this->authorize();
				break;
			case '/oauth/token':
				$this->token();
				break;
			case '/oauth/revoke':
				$this->revoke();
				break;
		}
	}

	/**
	 * Require authentication for the default MCP REST resource.
	 *
	 * Existing WordPress authentication such as Application Passwords remains valid.
	 *
	 * @param mixed $result Existing authentication result.
	 * @return mixed
	 */
	public function protect_mcp_rest_endpoint( $result ) {
		if ( null !== $result && false !== $result ) {
			return $result;
		}

		$route = isset( $GLOBALS['wp']->query_vars['rest_route'] ) ? (string) $GLOBALS['wp']->query_vars['rest_route'] : '';
		if ( '' === $route && isset( $_SERVER['REQUEST_URI'] ) ) {
			$route = (string) wp_parse_url( wp_unslash( $_SERVER['REQUEST_URI'] ), PHP_URL_PATH );
		}

		if ( false === strpos( $route, '/mcp/mcp-adapter-default-server' ) ) {
			return $result;
		}

		if ( get_current_user_id() > 0 ) {
			return $result;
		}

		return new \WP_Error(
			'wp_mcp_oauth_authentication_required',
			__( 'OAuth authentication is required for this MCP resource.', 'wp-mcp-oauth' ),
			array(
				'status' => 401,
			)
		);
	}

	/**
	 * Protected-resource metadata.
	 *
	 * @return void
	 */
	private function protected_resource_metadata() {
		$this->require_method( 'GET' );

		$this->json(
			array(
				'resource'              => self::resource_url(),
				'authorization_servers' => array( self::issuer() ),
				'scopes_supported'      => self::scopes(),
			)
		);
	}

	/**
	 * Authorization-server metadata.
	 *
	 * @return void
	 */
	private function authorization_server_metadata() {
		$this->require_method( 'GET' );

		$issuer = self::issuer();

		$this->json(
			array(
				'issuer'                                      => $issuer,
				'authorization_endpoint'                      => $issuer . '/oauth/authorize',
				'token_endpoint'                              => $issuer . '/oauth/token',
				'revocation_endpoint'                         => $issuer . '/oauth/revoke',
				'response_types_supported'                    => array( 'code' ),
				'grant_types_supported'                       => array( 'authorization_code', 'refresh_token' ),
				'code_challenge_methods_supported'            => array( 'S256' ),
				'token_endpoint_auth_methods_supported'       => array( 'none' ),
				'scopes_supported'                            => self::scopes(),
				'client_id_metadata_document_supported'       => true,
				'authorization_response_iss_parameter_supported' => true,
			)
		);
	}

	/**
	 * Authorization endpoint.
	 *
	 * @return void
	 */
	private function authorize() {
		if ( 'GET' !== $this->method() && 'POST' !== $this->method() ) {
			$this->oauth_error( 'invalid_request', 'Authorization endpoint requires GET or POST.', 405 );
		}

		$params = 'POST' === $this->method() ? wp_unslash( $_POST ) : wp_unslash( $_GET );

		$validated = $this->validate_authorization_request( $params );
		if ( is_wp_error( $validated ) ) {
			$this->oauth_error( $validated->get_error_code(), $validated->get_error_message(), 400 );
		}

		if ( ! is_user_logged_in() ) {
			$return_url = $this->current_url();
			wp_safe_redirect( wp_login_url( $return_url ) );
			exit;
		}

		if ( 'POST' === $this->method() ) {
			$nonce = isset( $params['_wpnonce'] ) ? sanitize_text_field( $params['_wpnonce'] ) : '';
			if ( ! wp_verify_nonce( $nonce, 'wp_mcp_oauth_authorize' ) ) {
				$this->oauth_error( 'access_denied', 'Invalid authorization confirmation.', 403 );
			}

			$decision = isset( $params['decision'] ) ? sanitize_key( $params['decision'] ) : 'deny';
			if ( 'allow' !== $decision ) {
				$this->redirect_authorization_error( $validated, 'access_denied' );
			}

			$code = $this->create_authorization_code( $validated );
			if ( is_wp_error( $code ) ) {
				$this->oauth_error( 'server_error', $code->get_error_message(), 500 );
			}

			$url = add_query_arg(
				array_filter(
					array(
						'code'  => $code,
						'state' => $validated['state'],
						'iss'   => self::issuer(),
					),
					static function ( $value ) {
						return '' !== $value;
					}
				),
				$validated['redirect_uri']
			);

			wp_redirect( $url ); // phpcs:ignore WordPress.Security.SafeRedirect.wp_redirect_wp_redirect
			exit;
		}

		$this->render_consent( $validated );
	}

	/**
	 * Validate authorization request.
	 *
	 * @param array $params Request parameters.
	 * @return array|\WP_Error
	 */
	private function validate_authorization_request( $params ) {
		$data = array(
			'response_type'         => isset( $params['response_type'] ) ? sanitize_text_field( $params['response_type'] ) : '',
			'client_id'             => isset( $params['client_id'] ) ? esc_url_raw( $params['client_id'] ) : '',
			'redirect_uri'          => isset( $params['redirect_uri'] ) ? esc_url_raw( $params['redirect_uri'] ) : '',
			'code_challenge'        => isset( $params['code_challenge'] ) ? sanitize_text_field( $params['code_challenge'] ) : '',
			'code_challenge_method' => isset( $params['code_challenge_method'] ) ? sanitize_text_field( $params['code_challenge_method'] ) : '',
			'resource'              => isset( $params['resource'] ) ? esc_url_raw( $params['resource'] ) : '',
			'scope'                 => isset( $params['scope'] ) ? sanitize_text_field( $params['scope'] ) : 'wordpress:read',
			'state'                 => isset( $params['state'] ) ? sanitize_text_field( $params['state'] ) : '',
		);

		if ( 'code' !== $data['response_type'] ) {
			return new \WP_Error( 'unsupported_response_type', 'Only authorization code flow is supported.' );
		}

		if ( ! $this->valid_chatgpt_client( $data['client_id'], $data['redirect_uri'] ) ) {
			return new \WP_Error( 'unauthorized_client', 'Unsupported OAuth client or redirect URI.' );
		}

		if ( 'S256' !== $data['code_challenge_method'] || ! preg_match( '/^[A-Za-z0-9_-]{43,128}$/', $data['code_challenge'] ) ) {
			return new \WP_Error( 'invalid_request', 'PKCE S256 is required.' );
		}

		if ( self::resource_url() !== $data['resource'] ) {
			return new \WP_Error( 'invalid_target', 'The OAuth resource does not match this MCP endpoint.' );
		}

		if ( ! $this->valid_scope_string( $data['scope'] ) ) {
			return new \WP_Error( 'invalid_scope', 'One or more requested scopes are not supported.' );
		}

		return $data;
	}

	/**
	 * Validate OpenAI-managed ChatGPT CIMD client and callback pair.
	 *
	 * @param string $client_id    Client metadata URL.
	 * @param string $redirect_uri Redirect URI.
	 * @return bool
	 */
	private function valid_chatgpt_client( $client_id, $redirect_uri ) {
		if ( 'https://chatgpt.com/oauth/client.json' === $client_id ) {
			return 'https://chatgpt.com/connector_platform_oauth_redirect' === $redirect_uri;
		}

		if ( ! preg_match( '#^https://chatgpt\.com/oauth/([A-Za-z0-9_-]+)/client\.json$#', $client_id, $client_match ) ) {
			return false;
		}

		if ( ! preg_match( '#^https://chatgpt\.com/connector/oauth/([A-Za-z0-9_-]+)$#', $redirect_uri, $redirect_match ) ) {
			return false;
		}

		return hash_equals( $client_match[1], $redirect_match[1] );
	}

	/**
	 * Validate scopes.
	 *
	 * @param string $scope Scope string.
	 * @return bool
	 */
	private function valid_scope_string( $scope ) {
		$requested = array_filter( preg_split( '/\s+/', trim( $scope ) ) );
		return empty( array_diff( $requested, self::scopes() ) );
	}

	/**
	 * Store authorization code.
	 *
	 * @param array $request Validated authorization request.
	 * @return string|\WP_Error
	 */
	private function create_authorization_code( $request ) {
		global $wpdb;

		$code = $this->random_token( 32 );

		$ok = $wpdb->insert(
			Database::codes_table(),
			array(
				'code_hash'             => Database::hash_secret( $code ),
				'user_id'               => get_current_user_id(),
				'client_id'             => $request['client_id'],
				'redirect_uri'          => $request['redirect_uri'],
				'resource'              => $request['resource'],
				'scope'                 => $request['scope'],
				'code_challenge'        => $request['code_challenge'],
				'code_challenge_method' => 'S256',
				'expires_at'            => Database::future( 300 ),
				'used_at'               => null,
				'created_at'            => Database::now(),
			),
			array( '%s', '%d', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s' )
		);

		if ( false === $ok ) {
			return new \WP_Error( 'database_error', 'Could not store the authorization code.' );
		}

		return $code;
	}

	/**
	 * Token endpoint.
	 *
	 * @return void
	 */
	private function token() {
		$this->require_method( 'POST' );

		$params     = wp_unslash( $_POST );
		$grant_type = isset( $params['grant_type'] ) ? sanitize_text_field( $params['grant_type'] ) : '';

		if ( 'authorization_code' === $grant_type ) {
			$this->exchange_authorization_code( $params );
		}

		if ( 'refresh_token' === $grant_type ) {
			$this->exchange_refresh_token( $params );
		}

		$this->oauth_error( 'unsupported_grant_type', 'Unsupported OAuth grant type.', 400 );
	}

	/**
	 * Exchange authorization code.
	 *
	 * @param array $params Request parameters.
	 * @return void
	 */
	private function exchange_authorization_code( $params ) {
		global $wpdb;

		$code          = isset( $params['code'] ) ? sanitize_text_field( $params['code'] ) : '';
		$client_id     = isset( $params['client_id'] ) ? esc_url_raw( $params['client_id'] ) : '';
		$redirect_uri  = isset( $params['redirect_uri'] ) ? esc_url_raw( $params['redirect_uri'] ) : '';
		$resource      = isset( $params['resource'] ) ? esc_url_raw( $params['resource'] ) : '';
		$code_verifier = isset( $params['code_verifier'] ) ? sanitize_text_field( $params['code_verifier'] ) : '';

		$table = Database::codes_table();
		$row   = $wpdb->get_row(
			$wpdb->prepare(
				"SELECT * FROM {$table} WHERE code_hash = %s AND used_at IS NULL AND expires_at > %s LIMIT 1",
				Database::hash_secret( $code ),
				Database::now()
			)
		);

		if ( ! $row ) {
			$this->oauth_error( 'invalid_grant', 'Authorization code is invalid or expired.', 400 );
		}

		if (
			! hash_equals( (string) $row->client_id, $client_id ) ||
			! hash_equals( (string) $row->redirect_uri, $redirect_uri ) ||
			! hash_equals( (string) $row->resource, $resource ) ||
			! hash_equals( (string) $row->code_challenge, $this->pkce_challenge( $code_verifier ) )
		) {
			$this->oauth_error( 'invalid_grant', 'Authorization code validation failed.', 400 );
		}

		$wpdb->update(
			$table,
			array( 'used_at' => Database::now() ),
			array( 'id' => (int) $row->id ),
			array( '%s' ),
			array( '%d' )
		);

		$this->issue_token_pair(
			(int) $row->user_id,
			(string) $row->client_id,
			(string) $row->resource,
			(string) $row->scope
		);
	}

	/**
	 * Exchange refresh token and rotate it.
	 *
	 * @param array $params Request parameters.
	 * @return void
	 */
	private function exchange_refresh_token( $params ) {
		global $wpdb;

		$refresh_token = isset( $params['refresh_token'] ) ? sanitize_text_field( $params['refresh_token'] ) : '';
		$client_id     = isset( $params['client_id'] ) ? esc_url_raw( $params['client_id'] ) : '';
		$resource      = isset( $params['resource'] ) ? esc_url_raw( $params['resource'] ) : '';

		$table = Database::tokens_table();
		$row   = $wpdb->get_row(
			$wpdb->prepare(
				"SELECT * FROM {$table}
				WHERE token_hash = %s
				AND token_type = 'refresh'
				AND revoked_at IS NULL
				AND expires_at > %s
				LIMIT 1",
				Database::hash_secret( $refresh_token ),
				Database::now()
			)
		);

		if ( ! $row || ! hash_equals( (string) $row->client_id, $client_id ) || ! hash_equals( (string) $row->resource, $resource ) ) {
			$this->oauth_error( 'invalid_grant', 'Refresh token is invalid or expired.', 400 );
		}

		$wpdb->update(
			$table,
			array( 'revoked_at' => Database::now() ),
			array( 'id' => (int) $row->id ),
			array( '%s' ),
			array( '%d' )
		);

		$this->issue_token_pair(
			(int) $row->user_id,
			(string) $row->client_id,
			(string) $row->resource,
			(string) $row->scope,
			(int) $row->id
		);
	}

	/**
	 * Issue access and refresh tokens.
	 *
	 * @param int    $user_id   User ID.
	 * @param string $client_id Client ID.
	 * @param string $resource  Resource.
	 * @param string $scope     Scope.
	 * @param int    $parent_id Previous refresh token row ID.
	 * @return void
	 */
	private function issue_token_pair( $user_id, $client_id, $resource, $scope, $parent_id = 0 ) {
		global $wpdb;

		$access  = $this->random_token( 32 );
		$refresh = $this->random_token( 48 );
		$table   = Database::tokens_table();

		$common = array(
			'user_id'    => $user_id,
			'client_id'  => $client_id,
			'resource'   => $resource,
			'scope'      => $scope,
			'revoked_at' => null,
			'parent_id'  => $parent_id ? $parent_id : null,
			'created_at' => Database::now(),
		);

		$wpdb->insert(
			$table,
			array_merge(
				$common,
				array(
					'token_hash' => Database::hash_secret( $access ),
					'token_type' => 'access',
					'expires_at' => Database::future( self::ACCESS_TTL ),
				)
			)
		);

		$wpdb->insert(
			$table,
			array_merge(
				$common,
				array(
					'token_hash' => Database::hash_secret( $refresh ),
					'token_type' => 'refresh',
					'expires_at' => Database::future( self::REFRESH_TTL ),
				)
			)
		);

		$this->json(
			array(
				'access_token'  => $access,
				'token_type'    => 'Bearer',
				'expires_in'    => self::ACCESS_TTL,
				'refresh_token' => $refresh,
				'scope'         => $scope,
			)
		);
	}

	/**
	 * Revoke an access or refresh token.
	 *
	 * @return void
	 */
	private function revoke() {
		global $wpdb;

		$this->require_method( 'POST' );

		$token = isset( $_POST['token'] ) ? sanitize_text_field( wp_unslash( $_POST['token'] ) ) : '';
		if ( '' !== $token ) {
			$wpdb->update(
				Database::tokens_table(),
				array( 'revoked_at' => Database::now() ),
				array( 'token_hash' => Database::hash_secret( $token ) ),
				array( '%s' ),
				array( '%s' )
			);
		}

		status_header( 200 );
		exit;
	}

	/**
	 * Render WordPress-hosted consent page.
	 *
	 * @param array $request Validated request.
	 * @return void
	 */
	private function render_consent( $request ) {
		$user = wp_get_current_user();

		status_header( 200 );
		nocache_headers();
		header( 'Content-Type: text/html; charset=' . get_option( 'blog_charset' ) );

		$fields = $request;
		?>
<!doctype html>
<html <?php language_attributes(); ?>>
<head>
	<meta charset="<?php bloginfo( 'charset' ); ?>">
	<meta name="viewport" content="width=device-width, initial-scale=1">
	<title><?php esc_html_e( 'Authorize ChatGPT', 'wp-mcp-oauth' ); ?></title>
	<?php wp_print_styles( 'dashicons' ); ?>
	<style>
		body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#f0f0f1;margin:0;padding:40px 20px;color:#1d2327}
		.card{max-width:620px;margin:0 auto;background:#fff;border:1px solid #dcdcde;border-radius:8px;padding:28px;box-shadow:0 1px 3px rgba(0,0,0,.06)}
		h1{margin-top:0}.scope{padding:10px 12px;background:#f6f7f7;border-radius:4px;margin:6px 0}
		.actions{display:flex;gap:10px;margin-top:24px}.button{border:0;border-radius:4px;padding:10px 16px;font-weight:600;cursor:pointer}
		.allow{background:#2271b1;color:#fff}.deny{background:#dcdcde;color:#1d2327}
	</style>
</head>
<body>
<div class="card">
	<h1><?php esc_html_e( 'Authorize ChatGPT', 'wp-mcp-oauth' ); ?></h1>
	<p>
		<?php
		printf(
			/* translators: %s: WordPress display name. */
			esc_html__( 'Signed in as %s. ChatGPT is requesting access to this WordPress MCP server.', 'wp-mcp-oauth' ),
			esc_html( $user->display_name )
		);
		?>
	</p>
	<?php foreach ( preg_split( '/\s+/', $request['scope'] ) as $scope ) : ?>
		<div class="scope"><?php echo esc_html( $scope ); ?></div>
	<?php endforeach; ?>
	<form method="post" action="<?php echo esc_url( self::issuer() . '/oauth/authorize' ); ?>">
		<?php foreach ( $fields as $name => $value ) : ?>
			<input type="hidden" name="<?php echo esc_attr( $name ); ?>" value="<?php echo esc_attr( $value ); ?>">
		<?php endforeach; ?>
		<?php wp_nonce_field( 'wp_mcp_oauth_authorize' ); ?>
		<div class="actions">
			<button class="button allow" type="submit" name="decision" value="allow"><?php esc_html_e( 'Allow', 'wp-mcp-oauth' ); ?></button>
			<button class="button deny" type="submit" name="decision" value="deny"><?php esc_html_e( 'Deny', 'wp-mcp-oauth' ); ?></button>
		</div>
	</form>
</div>
</body>
</html>
		<?php
		exit;
	}

	/**
	 * Redirect OAuth authorization error.
	 *
	 * @param array  $request Request.
	 * @param string $error   OAuth error.
	 * @return void
	 */
	private function redirect_authorization_error( $request, $error ) {
		$url = add_query_arg(
			array_filter(
				array(
					'error' => $error,
					'state' => $request['state'],
					'iss'   => self::issuer(),
				),
				static function ( $value ) {
					return '' !== $value;
				}
			),
			$request['redirect_uri']
		);

		wp_redirect( $url ); // phpcs:ignore WordPress.Security.SafeRedirect.wp_redirect_wp_redirect
		exit;
	}

	/**
	 * Current absolute URL.
	 *
	 * @return string
	 */
	private function current_url() {
		$scheme = is_ssl() ? 'https' : 'http';
		$host   = isset( $_SERVER['HTTP_HOST'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_HOST'] ) ) : wp_parse_url( home_url(), PHP_URL_HOST );
		$uri    = isset( $_SERVER['REQUEST_URI'] ) ? wp_unslash( $_SERVER['REQUEST_URI'] ) : '/';

		return $scheme . '://' . $host . $uri;
	}

	/**
	 * PKCE challenge.
	 *
	 * @param string $verifier Code verifier.
	 * @return string
	 */
	private function pkce_challenge( $verifier ) {
		return rtrim( strtr( base64_encode( hash( 'sha256', $verifier, true ) ), '+/', '-_' ), '=' );
	}

	/**
	 * Cryptographically random URL-safe token.
	 *
	 * @param int $bytes Random bytes.
	 * @return string
	 */
	private function random_token( $bytes ) {
		return rtrim( strtr( base64_encode( random_bytes( (int) $bytes ) ), '+/', '-_' ), '=' );
	}

	/**
	 * Request method.
	 *
	 * @return string
	 */
	private function method() {
		return isset( $_SERVER['REQUEST_METHOD'] ) ? strtoupper( sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) ) : 'GET';
	}

	/**
	 * Require method.
	 *
	 * @param string $method Method.
	 * @return void
	 */
	private function require_method( $method ) {
		if ( $method !== $this->method() ) {
			$this->oauth_error( 'invalid_request', 'Unsupported HTTP method.', 405 );
		}
	}

	/**
	 * JSON response.
	 *
	 * @param array $data Data.
	 * @param int   $status Status.
	 * @return void
	 */
	private function json( $data, $status = 200 ) {
		status_header( $status );
		nocache_headers();
		header( 'Content-Type: application/json; charset=UTF-8' );
		echo wp_json_encode( $data );
		exit;
	}

	/**
	 * OAuth error response.
	 *
	 * @param string $error       Error code.
	 * @param string $description Description.
	 * @param int    $status      HTTP status.
	 * @return void
	 */
	private function oauth_error( $error, $description, $status ) {
		$this->json(
			array(
				'error'             => $error,
				'error_description' => $description,
			),
			$status
		);
	}
}

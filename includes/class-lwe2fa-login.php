<?php
/**
 * Login flow: intercepts successful password logins and requires the emailed code.
 *
 * @package Lightweight_Email_2FA
 */

defined( 'ABSPATH' ) || exit;

/**
 * Handles the second login step on wp-login.php.
 */
class LWE2FA_Login {

	const ACTION = 'lwe2fa';
	const COOKIE = 'lwe2fa_challenge';
	const NONCE  = 'lwe2fa_verify';

	/**
	 * Session token created by the password login, destroyed before the second step.
	 *
	 * @var string
	 */
	private static $session_token = '';

	/**
	 * Register hooks.
	 */
	public static function init() {
		add_action( 'set_logged_in_cookie', array( __CLASS__, 'capture_session_token' ), 10, 6 );
		// Run early so no other wp_login callback can act on the half-finished login.
		add_action( 'wp_login', array( __CLASS__, 'on_wp_login' ), 1, 2 );
		add_action( 'login_form_' . self::ACTION, array( __CLASS__, 'handle_challenge' ) );
		add_filter( 'wp_login_errors', array( __CLASS__, 'login_errors' ) );
		add_filter( 'authenticate', array( __CLASS__, 'block_api_password_login' ), 100 );
	}

	/**
	 * Remember the session token so it can be destroyed if 2FA is required.
	 *
	 * @param string $cookie     Cookie value.
	 * @param int    $expire     Cookie expiry.
	 * @param int    $expiration Session expiration.
	 * @param int    $user_id    User ID.
	 * @param string $scheme     Scheme.
	 * @param string $token      Session token.
	 */
	public static function capture_session_token( $cookie, $expire, $expiration, $user_id, $scheme, $token ) {
		self::$session_token = (string) $token;
	}

	/**
	 * After a successful password login, undo it and start the email challenge.
	 *
	 * @param string  $user_login Username.
	 * @param WP_User $user       User.
	 */
	public static function on_wp_login( $user_login, $user ) {
		if ( ! LWE2FA_Core::is_enabled_for_user( $user ) ) {
			return;
		}

		// Undo the login that wp_signon() just performed.
		if ( '' !== self::$session_token ) {
			WP_Session_Tokens::get_instance( $user->ID )->destroy( self::$session_token );
			self::$session_token = '';
		}
		wp_clear_auth_cookie();
		wp_set_current_user( 0 );

		// phpcs:disable WordPress.Security.NonceVerification -- Core login form fields; wp-login.php has no nonce.
		$remember    = ! empty( $_POST['rememberme'] );
		$redirect_to = isset( $_REQUEST['redirect_to'] ) ? esc_url_raw( wp_unslash( $_REQUEST['redirect_to'] ) ) : '';
		// phpcs:enable

		$token = LWE2FA_Core::start_challenge( $user, $remember, $redirect_to );
		if ( is_wp_error( $token ) ) {
			self::redirect_to_login( 'mail' );
		}

		self::set_cookie( $user->ID . '|' . $token, time() + LWE2FA_Core::code_ttl() + HOUR_IN_SECONDS );
		wp_safe_redirect( self::challenge_url() );
		exit;
	}

	/**
	 * Display and process the verification form (wp-login.php?action=lwe2fa).
	 */
	public static function handle_challenge() {
		nocache_headers();

		list( $user_id, $token ) = self::read_cookie();
		$user                    = $user_id ? get_userdata( $user_id ) : false;
		$pending                 = $user ? LWE2FA_Core::get_pending( $user_id, $token ) : false;

		if ( ! $user || ! $pending ) {
			self::clear_cookie();
			self::redirect_to_login( 'expired' );
		}

		$errors = new WP_Error();

		if ( isset( $_SERVER['REQUEST_METHOD'] ) && 'POST' === $_SERVER['REQUEST_METHOD'] ) {
			if ( ! isset( $_POST['_lwe2fa_nonce'] ) || ! wp_verify_nonce( sanitize_key( wp_unslash( $_POST['_lwe2fa_nonce'] ) ), self::NONCE ) ) {
				$errors->add( 'lwe2fa_nonce', __( 'Your session has expired. Please try again.', 'lightweight-email-2fa' ) );
			} elseif ( isset( $_POST['lwe2fa_resend'] ) ) {
				self::resend( $user, $pending, $errors );
			} else {
				$code   = isset( $_POST['lwe2fa_code'] ) ? sanitize_text_field( wp_unslash( $_POST['lwe2fa_code'] ) ) : '';
				$result = LWE2FA_Core::verify_code( $user, $pending, $code );

				if ( true === $result ) {
					self::complete_login( $user, $pending );
				}
				if ( in_array( $result->get_error_code(), array( 'lwe2fa_too_many', 'lwe2fa_locked' ), true ) ) {
					self::clear_cookie();
					self::redirect_to_login( 'lwe2fa_locked' === $result->get_error_code() ? 'locked' : 'too_many' );
				}
				$errors = $result;
			}
		}

		self::render_form( $user, $errors );
		exit;
	}

	/**
	 * Send a new code, respecting the resend limit and cooldown.
	 *
	 * @param WP_User  $user    User.
	 * @param array    $pending Pending challenge.
	 * @param WP_Error $errors  Collects errors and notices.
	 */
	private static function resend( $user, array $pending, WP_Error $errors ) {
		$wait = LWE2FA_Core::RESEND_DELAY - ( time() - (int) $pending['sent_at'] );

		if ( (int) $pending['resends'] >= LWE2FA_Core::MAX_RESENDS ) {
			$errors->add( 'lwe2fa_resend_limit', __( 'You have requested too many codes. Please log in again.', 'lightweight-email-2fa' ) );
		} elseif ( $wait > 0 ) {
			/* translators: %d: Number of seconds. */
			$errors->add( 'lwe2fa_resend_wait', sprintf( _n( 'Please wait %d second before requesting a new code.', 'Please wait %d seconds before requesting a new code.', $wait, 'lightweight-email-2fa' ), $wait ) );
		} else {
			$pending['resends'] = (int) $pending['resends'] + 1;
			$sent               = LWE2FA_Core::send_new_code( $user, $pending );
			if ( is_wp_error( $sent ) ) {
				self::clear_cookie();
				self::redirect_to_login( 'mail' );
			}
			$errors->add( 'lwe2fa_resent', __( 'A new code has been sent to your email address.', 'lightweight-email-2fa' ), 'message' );
		}
	}

	/**
	 * Log the user in and redirect, mirroring wp-login.php behaviour.
	 *
	 * @param WP_User $user    User.
	 * @param array   $pending Pending challenge.
	 */
	private static function complete_login( $user, array $pending ) {
		self::clear_cookie();
		wp_set_auth_cookie( $user->ID, ! empty( $pending['remember'] ), is_ssl() );
		wp_set_current_user( $user->ID );

		/**
		 * Fires after a user has passed email two-factor authentication.
		 *
		 * @param WP_User $user User.
		 */
		do_action( 'lwe2fa_authenticated', $user );

		$requested   = isset( $pending['redirect_to'] ) ? (string) $pending['redirect_to'] : '';
		$redirect_to = '' !== $requested ? $requested : admin_url();

		/** This filter is documented in wp-login.php */
		$redirect_to = apply_filters( 'login_redirect', $redirect_to, $requested, $user ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Core hook.

		if ( ( empty( $redirect_to ) || 'wp-admin/' === $redirect_to || admin_url() === $redirect_to ) && ! $user->has_cap( 'edit_posts' ) ) {
			$redirect_to = $user->has_cap( 'read' ) ? admin_url( 'profile.php' ) : home_url();
		}

		wp_safe_redirect( $redirect_to );
		exit;
	}

	/**
	 * Output the verification form using the core login page template.
	 *
	 * @param WP_User  $user   User.
	 * @param WP_Error $errors Errors and notices.
	 */
	private static function render_form( $user, WP_Error $errors ) {
		$message = sprintf(
			/* translators: %s: Masked email address. */
			__( 'We emailed a verification code to %s. Enter it below to finish logging in.', 'lightweight-email-2fa' ),
			'<strong>' . esc_html( LWE2FA_Core::mask_email( $user->user_email ) ) . '</strong>'
		);

		login_header( __( 'Verification code', 'lightweight-email-2fa' ), '<p class="message">' . $message . '</p>', $errors );
		?>
		<form name="lwe2fa_form" id="loginform" action="<?php echo esc_url( self::challenge_url() ); ?>" method="post" autocomplete="off">
			<p>
				<label for="lwe2fa_code"><?php esc_html_e( 'Verification code', 'lightweight-email-2fa' ); ?></label>
				<input type="text" name="lwe2fa_code" id="lwe2fa_code" class="input" value="" size="20" inputmode="numeric" pattern="[0-9 ]*" maxlength="<?php echo esc_attr( LWE2FA_Core::CODE_LENGTH + 2 ); ?>" autocomplete="one-time-code" required autofocus />
			</p>
			<?php wp_nonce_field( self::NONCE, '_lwe2fa_nonce' ); ?>
			<p class="submit">
				<input type="submit" name="wp-submit" id="wp-submit" class="button button-primary button-large" value="<?php esc_attr_e( 'Verify', 'lightweight-email-2fa' ); ?>" />
			</p>
			<p style="clear:both;padding-top:16px;">
				<input type="submit" name="lwe2fa_resend" class="button-link" value="<?php esc_attr_e( 'Resend code', 'lightweight-email-2fa' ); ?>" formnovalidate />
			</p>
		</form>
		<p id="nav"><a href="<?php echo esc_url( wp_login_url() ); ?>"><?php esc_html_e( '&larr; Back to login', 'lightweight-email-2fa' ); ?></a></p>
		<?php
		login_footer( 'lwe2fa_code' );
	}

	/**
	 * Show plugin errors on the normal login screen after a redirect.
	 *
	 * @param WP_Error $errors Login errors.
	 * @return WP_Error
	 */
	public static function login_errors( $errors ) {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Display-only status flag.
		$code     = isset( $_GET['lwe2fa_error'] ) ? sanitize_key( wp_unslash( $_GET['lwe2fa_error'] ) ) : '';
		$messages = array(
			'expired'  => __( 'Your verification session has expired. Please log in again.', 'lightweight-email-2fa' ),
			'too_many' => __( 'Too many incorrect codes. Please log in again.', 'lightweight-email-2fa' ),
			'locked'   => __( 'Too many incorrect codes. Please wait 15 minutes and log in again.', 'lightweight-email-2fa' ),
			'mail'     => __( 'The verification email could not be sent. Please contact the site administrator.', 'lightweight-email-2fa' ),
		);
		if ( isset( $messages[ $code ] ) && $errors instanceof WP_Error ) {
			$errors->add( 'lwe2fa_' . $code, $messages[ $code ] );
		}
		return $errors;
	}

	/**
	 * Block password logins over XML-RPC for users with 2FA (application passwords still work).
	 *
	 * @param WP_User|WP_Error|null $user Authentication result.
	 * @return WP_User|WP_Error|null
	 */
	public static function block_api_password_login( $user ) {
		if ( ! $user instanceof WP_User || ! defined( 'XMLRPC_REQUEST' ) || ! XMLRPC_REQUEST ) {
			return $user;
		}
		if ( did_action( 'application_password_did_authenticate' ) ) {
			return $user;
		}
		if ( LWE2FA_Core::is_enabled_for_user( $user ) ) {
			return new WP_Error( 'lwe2fa_api_blocked', __( 'Password login over XML-RPC is disabled for accounts using two-factor authentication. Use an application password instead.', 'lightweight-email-2fa' ) );
		}
		return $user;
	}

	/**
	 * URL of the verification screen.
	 *
	 * @return string
	 */
	private static function challenge_url() {
		return add_query_arg( 'action', self::ACTION, site_url( 'wp-login.php', 'login_post' ) );
	}

	/**
	 * Redirect to the login screen with an error flag and stop.
	 *
	 * @param string $error Error key.
	 */
	private static function redirect_to_login( $error ) {
		wp_safe_redirect( add_query_arg( 'lwe2fa_error', $error, wp_login_url() ) );
		exit;
	}

	/**
	 * Read user ID and token from the challenge cookie.
	 *
	 * @return array{0:int,1:string}
	 */
	private static function read_cookie() {
		$value = isset( $_COOKIE[ self::COOKIE ] ) ? sanitize_text_field( wp_unslash( $_COOKIE[ self::COOKIE ] ) ) : '';
		if ( ! preg_match( '/^(\d+)\|([a-f0-9]{64})$/', $value, $m ) ) {
			return array( 0, '' );
		}
		return array( (int) $m[1], $m[2] );
	}

	/**
	 * Set the HttpOnly challenge cookie.
	 *
	 * @param string $value  Value.
	 * @param int    $expire Expiry timestamp.
	 */
	private static function set_cookie( $value, $expire ) {
		setcookie(
			self::COOKIE,
			$value,
			array(
				'expires'  => $expire,
				'path'     => SITECOOKIEPATH,
				'domain'   => COOKIE_DOMAIN,
				'secure'   => is_ssl(),
				'httponly' => true,
				'samesite' => 'Lax',
			)
		);
	}

	/**
	 * Remove the challenge cookie.
	 */
	private static function clear_cookie() {
		self::set_cookie( '', time() - YEAR_IN_SECONDS );
	}
}

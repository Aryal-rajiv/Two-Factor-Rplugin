<?php
/**
 * Core helpers: settings, per-user status, code generation, storage and email.
 *
 * @package Lightweight_Email_2FA
 */

defined( 'ABSPATH' ) || exit;

/**
 * Core functionality shared by the login flow, profile and settings screens.
 */
class LWE2FA_Core {

	const OPTION        = 'lwe2fa_settings';
	const META_ENABLED  = 'lwe2fa_enabled';
	const META_PENDING  = 'lwe2fa_pending';
	const META_LOCKOUT  = 'lwe2fa_lockout';
	const CODE_LENGTH   = 6;
	const MAX_ATTEMPTS  = 5;
	const MAX_RESENDS   = 3;
	const RESEND_DELAY  = 60;
	const LOCKOUT_LIMIT = 10;
	const LOCKOUT_TIME  = 900;

	/**
	 * Get plugin settings merged with defaults.
	 *
	 * @return array
	 */
	public static function get_settings() {
		$defaults = array(
			'enforced_roles' => array(),
			'code_ttl'       => 10,
		);
		$settings = get_option( self::OPTION, array() );
		return wp_parse_args( is_array( $settings ) ? $settings : array(), $defaults );
	}

	/**
	 * Code lifetime in seconds.
	 *
	 * @return int
	 */
	public static function code_ttl() {
		$settings = self::get_settings();
		return max( 1, min( 60, absint( $settings['code_ttl'] ) ) ) * MINUTE_IN_SECONDS;
	}

	/**
	 * Whether 2FA is enforced for one of the user's roles.
	 *
	 * @param WP_User $user User.
	 * @return bool
	 */
	public static function is_enforced_for_user( $user ) {
		$settings = self::get_settings();
		return (bool) array_intersect( (array) $user->roles, (array) $settings['enforced_roles'] );
	}

	/**
	 * Whether email 2FA applies to the given user.
	 *
	 * Define LWE2FA_DISABLE as true in wp-config.php to temporarily bypass
	 * the second step (e.g. if outgoing email is broken and you are locked out).
	 *
	 * @param WP_User $user User.
	 * @return bool
	 */
	public static function is_enabled_for_user( $user ) {
		if ( defined( 'LWE2FA_DISABLE' ) && LWE2FA_DISABLE ) {
			return false;
		}
		if ( ! $user instanceof WP_User || ! $user->exists() ) {
			return false;
		}
		$enabled = self::is_enforced_for_user( $user ) || '1' === get_user_meta( $user->ID, self::META_ENABLED, true );

		/**
		 * Filter whether email two-factor authentication is required for a user.
		 *
		 * @param bool    $enabled Whether 2FA is required.
		 * @param WP_User $user    The user.
		 */
		return (bool) apply_filters( 'lwe2fa_enabled_for_user', $enabled, $user );
	}

	/**
	 * Keyed hash used for codes and challenge tokens, so raw values are never stored.
	 *
	 * @param string $value Value to hash.
	 * @return string
	 */
	public static function hash( $value ) {
		return hash_hmac( 'sha256', (string) $value, wp_salt( 'auth' ) );
	}

	/**
	 * Generate a numeric one-time code using a CSPRNG.
	 *
	 * @return string
	 */
	public static function generate_code() {
		$code = '';
		for ( $i = 0; $i < self::CODE_LENGTH; $i++ ) {
			$code .= (string) random_int( 0, 9 );
		}
		return $code;
	}

	/**
	 * Start a new challenge: create a token, generate and email a code.
	 *
	 * @param WP_User $user        User.
	 * @param bool    $remember    Whether "Remember Me" was checked.
	 * @param string  $redirect_to Requested redirect after login.
	 * @return string|WP_Error Raw challenge token, or error.
	 */
	public static function start_challenge( $user, $remember, $redirect_to ) {
		$token   = bin2hex( random_bytes( 32 ) );
		$pending = array(
			'token'       => self::hash( $token ),
			'remember'    => (bool) $remember,
			'redirect_to' => $redirect_to,
			'resends'     => 0,
		);

		$sent = self::send_new_code( $user, $pending );
		if ( is_wp_error( $sent ) ) {
			return $sent;
		}
		return $token;
	}

	/**
	 * Generate a fresh code, store its hash and email it.
	 *
	 * @param WP_User $user    User.
	 * @param array   $pending Pending challenge data (modified and saved).
	 * @return true|WP_Error
	 */
	public static function send_new_code( $user, array $pending ) {
		$code = self::generate_code();

		$pending['code']     = self::hash( $code . '|' . $user->ID );
		$pending['expires']  = time() + self::code_ttl();
		$pending['sent_at']  = time();
		$pending['attempts'] = 0;
		update_user_meta( $user->ID, self::META_PENDING, $pending );

		if ( ! self::send_email( $user, $code ) ) {
			delete_user_meta( $user->ID, self::META_PENDING );
			return new WP_Error( 'lwe2fa_mail_failed', __( 'The verification email could not be sent. Please contact the site administrator.', 'lightweight-email-2fa' ) );
		}
		return true;
	}

	/**
	 * Get the pending challenge if the supplied token matches.
	 *
	 * @param int    $user_id User ID.
	 * @param string $token   Raw challenge token.
	 * @return array|false
	 */
	public static function get_pending( $user_id, $token ) {
		$pending = get_user_meta( $user_id, self::META_PENDING, true );
		if ( ! is_array( $pending ) || empty( $pending['token'] ) || '' === $token ) {
			return false;
		}
		if ( ! hash_equals( $pending['token'], self::hash( $token ) ) ) {
			return false;
		}
		return $pending;
	}

	/**
	 * Clear any pending challenge for a user.
	 *
	 * @param int $user_id User ID.
	 */
	public static function clear_pending( $user_id ) {
		delete_user_meta( $user_id, self::META_PENDING );
	}

	/**
	 * Whether the user is temporarily locked out after too many wrong codes.
	 *
	 * @param int $user_id User ID.
	 * @return bool
	 */
	public static function is_locked_out( $user_id ) {
		$lock = get_user_meta( $user_id, self::META_LOCKOUT, true );
		if ( ! is_array( $lock ) || empty( $lock['since'] ) ) {
			return false;
		}
		if ( time() - (int) $lock['since'] > self::LOCKOUT_TIME ) {
			delete_user_meta( $user_id, self::META_LOCKOUT );
			return false;
		}
		return (int) $lock['count'] >= self::LOCKOUT_LIMIT;
	}

	/**
	 * Record a failed verification attempt for lockout purposes.
	 *
	 * @param int $user_id User ID.
	 */
	public static function record_failure( $user_id ) {
		$lock = get_user_meta( $user_id, self::META_LOCKOUT, true );
		if ( ! is_array( $lock ) || empty( $lock['since'] ) || time() - (int) $lock['since'] > self::LOCKOUT_TIME ) {
			$lock = array(
				'count' => 0,
				'since' => time(),
			);
		}
		++$lock['count'];
		update_user_meta( $user_id, self::META_LOCKOUT, $lock );
	}

	/**
	 * Verify a submitted code against the pending challenge.
	 *
	 * @param WP_User $user    User.
	 * @param array   $pending Pending challenge (already token-validated).
	 * @param string  $code    Submitted code.
	 * @return true|WP_Error
	 */
	public static function verify_code( $user, array $pending, $code ) {
		if ( self::is_locked_out( $user->ID ) ) {
			self::clear_pending( $user->ID );
			return new WP_Error( 'lwe2fa_locked', __( 'Too many incorrect codes. Please wait 15 minutes and log in again.', 'lightweight-email-2fa' ) );
		}

		if ( empty( $pending['expires'] ) || time() > (int) $pending['expires'] ) {
			return new WP_Error( 'lwe2fa_expired', __( 'This code has expired. Please request a new code.', 'lightweight-email-2fa' ) );
		}

		$code = preg_replace( '/\D/', '', (string) $code );
		if ( '' !== $code && hash_equals( (string) $pending['code'], self::hash( $code . '|' . $user->ID ) ) ) {
			self::clear_pending( $user->ID );
			delete_user_meta( $user->ID, self::META_LOCKOUT );
			return true;
		}

		self::record_failure( $user->ID );
		$pending['attempts'] = (int) $pending['attempts'] + 1;
		if ( $pending['attempts'] >= self::MAX_ATTEMPTS ) {
			self::clear_pending( $user->ID );
			return new WP_Error( 'lwe2fa_too_many', __( 'Too many incorrect codes. Please log in again.', 'lightweight-email-2fa' ) );
		}
		update_user_meta( $user->ID, self::META_PENDING, $pending );
		return new WP_Error( 'lwe2fa_invalid', __( 'Incorrect verification code. Please try again.', 'lightweight-email-2fa' ) );
	}

	/**
	 * Email the code to the user.
	 *
	 * @param WP_User $user User.
	 * @param string  $code Plain code.
	 * @return bool
	 */
	public static function send_email( $user, $code ) {
		$site    = wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES );
		$minutes = (int) ( self::code_ttl() / MINUTE_IN_SECONDS );
		$ip      = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';

		/* translators: %s: Site name. */
		$subject = sprintf( __( '[%s] Your login verification code', 'lightweight-email-2fa' ), $site );

		$lines = array(
			/* translators: %s: User display name. */
			sprintf( __( 'Hello %s,', 'lightweight-email-2fa' ), $user->display_name ),
			'',
			/* translators: %s: Site name. */
			sprintf( __( 'Your verification code for %s is:', 'lightweight-email-2fa' ), $site ),
			'',
			$code,
			'',
			/* translators: %d: Number of minutes. */
			sprintf( _n( 'This code expires in %d minute.', 'This code expires in %d minutes.', $minutes, 'lightweight-email-2fa' ), $minutes ),
		);
		if ( '' !== $ip ) {
			/* translators: %s: IP address. */
			$lines[] = sprintf( __( 'Login attempt from IP address: %s', 'lightweight-email-2fa' ), $ip );
		}
		$lines[] = '';
		$lines[] = __( 'If you did not try to log in, someone may know your password. Please change it immediately.', 'lightweight-email-2fa' );

		/**
		 * Filter the verification email subject.
		 *
		 * @param string  $subject Subject.
		 * @param WP_User $user    User.
		 */
		$subject = apply_filters( 'lwe2fa_email_subject', $subject, $user );

		/**
		 * Filter the verification email message (plain text).
		 *
		 * @param string  $message Message.
		 * @param string  $code    The one-time code.
		 * @param WP_User $user    User.
		 */
		$message = apply_filters( 'lwe2fa_email_message', implode( "\n", $lines ), $code, $user );

		return (bool) wp_mail( $user->user_email, $subject, $message );
	}

	/**
	 * Partially mask an email address for display, e.g. jo***@example.com.
	 *
	 * @param string $email Email.
	 * @return string
	 */
	public static function mask_email( $email ) {
		$parts = explode( '@', (string) $email, 2 );
		if ( 2 !== count( $parts ) ) {
			return '';
		}
		$local = $parts[0];
		$keep  = min( 2, max( 1, strlen( $local ) - 1 ) );
		return substr( $local, 0, $keep ) . str_repeat( '*', max( 3, strlen( $local ) - $keep ) ) . '@' . $parts[1];
	}
}

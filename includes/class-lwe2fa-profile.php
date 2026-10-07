<?php
/**
 * User profile option to enable email two-factor authentication.
 *
 * @package Lightweight_Email_2FA
 */

defined( 'ABSPATH' ) || exit;

/**
 * Adds an opt-in checkbox to the user profile screens.
 */
class LWE2FA_Profile {

	const NONCE = 'lwe2fa_profile';

	/**
	 * Register hooks.
	 */
	public static function init() {
		add_action( 'show_user_profile', array( __CLASS__, 'render' ) );
		add_action( 'edit_user_profile', array( __CLASS__, 'render' ) );
		add_action( 'personal_options_update', array( __CLASS__, 'save' ) );
		add_action( 'edit_user_profile_update', array( __CLASS__, 'save' ) );
	}

	/**
	 * Render the profile section.
	 *
	 * @param WP_User $user User being edited.
	 */
	public static function render( $user ) {
		if ( ! current_user_can( 'edit_user', $user->ID ) ) {
			return;
		}
		$enforced = LWE2FA_Core::is_enforced_for_user( $user );
		$enabled  = $enforced || '1' === get_user_meta( $user->ID, LWE2FA_Core::META_ENABLED, true );
		?>
		<h2><?php esc_html_e( 'Two-Factor Authentication', 'lightweight-email-2fa' ); ?></h2>
		<table class="form-table" role="presentation">
			<tr>
				<th scope="row"><?php esc_html_e( 'Email verification code', 'lightweight-email-2fa' ); ?></th>
				<td>
					<?php wp_nonce_field( self::NONCE, '_lwe2fa_profile_nonce' ); ?>
					<label for="lwe2fa_enabled">
						<input type="checkbox" name="lwe2fa_enabled" id="lwe2fa_enabled" value="1" <?php checked( $enabled ); ?> <?php disabled( $enforced ); ?> />
						<?php esc_html_e( 'Require a code sent to my email address when logging in', 'lightweight-email-2fa' ); ?>
					</label>
					<p class="description">
						<?php
						if ( $enforced ) {
							esc_html_e( 'Two-factor authentication is required for this user role by the site administrator.', 'lightweight-email-2fa' );
						} else {
							esc_html_e( 'Make sure the email address above is correct and that you can receive email from this site before enabling.', 'lightweight-email-2fa' );
						}
						?>
					</p>
				</td>
			</tr>
		</table>
		<?php
	}

	/**
	 * Save the profile option.
	 *
	 * @param int $user_id User ID.
	 */
	public static function save( $user_id ) {
		if ( ! current_user_can( 'edit_user', $user_id ) ) {
			return;
		}
		if ( ! isset( $_POST['_lwe2fa_profile_nonce'] ) || ! wp_verify_nonce( sanitize_key( wp_unslash( $_POST['_lwe2fa_profile_nonce'] ) ), self::NONCE ) ) {
			return;
		}
		if ( ! empty( $_POST['lwe2fa_enabled'] ) ) {
			update_user_meta( $user_id, LWE2FA_Core::META_ENABLED, '1' );
		} else {
			delete_user_meta( $user_id, LWE2FA_Core::META_ENABLED );
		}
	}
}

<?php
/**
 * Settings screen (Settings > Email 2FA).
 *
 * @package Lightweight_Email_2FA
 */

defined( 'ABSPATH' ) || exit;

/**
 * Registers and renders plugin settings.
 */
class LWE2FA_Settings {

	const PAGE = 'lightweight-email-2fa';

	/**
	 * Register hooks.
	 */
	public static function init() {
		add_action( 'admin_menu', array( __CLASS__, 'add_page' ) );
		add_action( 'admin_init', array( __CLASS__, 'register' ) );
	}

	/**
	 * Add the settings page.
	 */
	public static function add_page() {
		add_options_page(
			__( 'Email Two-Factor Authentication', 'lightweight-email-2fa' ),
			__( 'Email 2FA', 'lightweight-email-2fa' ),
			'manage_options',
			self::PAGE,
			array( __CLASS__, 'render_page' )
		);
	}

	/**
	 * Register the setting and fields.
	 */
	public static function register() {
		register_setting(
			self::PAGE,
			LWE2FA_Core::OPTION,
			array(
				'type'              => 'array',
				'sanitize_callback' => array( __CLASS__, 'sanitize' ),
				'default'           => array(
					'enforced_roles' => array(),
					'code_ttl'       => 10,
				),
			)
		);

		add_settings_section( 'lwe2fa_main', '', '__return_false', self::PAGE );

		add_settings_field( 'lwe2fa_roles', __( 'Require for roles', 'lightweight-email-2fa' ), array( __CLASS__, 'field_roles' ), self::PAGE, 'lwe2fa_main' );
		add_settings_field( 'lwe2fa_ttl', __( 'Code expiry', 'lightweight-email-2fa' ), array( __CLASS__, 'field_ttl' ), self::PAGE, 'lwe2fa_main', array( 'label_for' => 'lwe2fa_code_ttl' ) );
	}

	/**
	 * Sanitize settings.
	 *
	 * @param mixed $input Raw input.
	 * @return array
	 */
	public static function sanitize( $input ) {
		$input = is_array( $input ) ? $input : array();
		$roles = array_keys( wp_roles()->get_names() );

		$enforced = isset( $input['enforced_roles'] ) ? array_map( 'sanitize_key', (array) $input['enforced_roles'] ) : array();
		$ttl      = isset( $input['code_ttl'] ) ? absint( $input['code_ttl'] ) : 10;

		return array(
			'enforced_roles' => array_values( array_intersect( $enforced, $roles ) ),
			'code_ttl'       => max( 1, min( 60, $ttl ) ),
		);
	}

	/**
	 * Role checkboxes.
	 */
	public static function field_roles() {
		$settings = LWE2FA_Core::get_settings();
		echo '<fieldset>';
		foreach ( wp_roles()->get_names() as $role => $name ) {
			printf(
				'<label><input type="checkbox" name="%1$s[enforced_roles][]" value="%2$s" %3$s /> %4$s</label><br />',
				esc_attr( LWE2FA_Core::OPTION ),
				esc_attr( $role ),
				checked( in_array( $role, (array) $settings['enforced_roles'], true ), true, false ),
				esc_html( translate_user_role( $name ) )
			);
		}
		echo '</fieldset>';
		echo '<p class="description">' . esc_html__( 'Users with these roles must enter an emailed code on every login. Other users can opt in from their profile.', 'lightweight-email-2fa' ) . '</p>';
	}

	/**
	 * Code expiry input.
	 */
	public static function field_ttl() {
		$settings = LWE2FA_Core::get_settings();
		printf(
			'<input type="number" id="lwe2fa_code_ttl" name="%1$s[code_ttl]" value="%2$d" min="1" max="60" class="small-text" /> %3$s',
			esc_attr( LWE2FA_Core::OPTION ),
			absint( $settings['code_ttl'] ),
			esc_html__( 'minutes', 'lightweight-email-2fa' )
		);
	}

	/**
	 * Render the settings page.
	 */
	public static function render_page() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		?>
		<div class="wrap">
			<h1><?php echo esc_html( get_admin_page_title() ); ?></h1>
			<form action="options.php" method="post">
				<?php
				settings_fields( self::PAGE );
				do_settings_sections( self::PAGE );
				submit_button();
				?>
			</form>
			<h2><?php esc_html_e( 'Locked out?', 'lightweight-email-2fa' ); ?></h2>
			<p>
				<?php
				printf(
					/* translators: %s: PHP constant definition. */
					esc_html__( 'If email delivery stops working, add %s to wp-config.php to temporarily skip the code step, fix email, then remove it.', 'lightweight-email-2fa' ),
					"<code>define( 'LWE2FA_DISABLE', true );</code>"
				);
				?>
			</p>
		</div>
		<?php
	}
}

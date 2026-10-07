<?php
/**
 * Plugin Name:       Lightweight Email 2FA
 * Description:       Simple, lightweight two-factor authentication that emails a one-time login code after the password is accepted.
 * Version:           1.0.0
 * Requires at least: 5.8
 * Requires PHP:      7.4
 * Author:            Rajiv Aryal
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       lightweight-email-2fa
 *
 * @package Lightweight_Email_2FA
 */

defined( 'ABSPATH' ) || exit;

define( 'LWE2FA_VERSION', '1.0.0' );
define( 'LWE2FA_FILE', __FILE__ );
define( 'LWE2FA_DIR', plugin_dir_path( __FILE__ ) );

require_once LWE2FA_DIR . 'includes/class-lwe2fa-core.php';
require_once LWE2FA_DIR . 'includes/class-lwe2fa-login.php';
require_once LWE2FA_DIR . 'includes/class-lwe2fa-profile.php';
require_once LWE2FA_DIR . 'includes/class-lwe2fa-settings.php';

LWE2FA_Login::init();
LWE2FA_Profile::init();
LWE2FA_Settings::init();

/**
 * Add a "Settings" link on the Plugins screen.
 *
 * @param array $links Existing action links.
 * @return array
 */
function lwe2fa_action_links( $links ) {
	$url = admin_url( 'options-general.php?page=lightweight-email-2fa' );
	array_unshift( $links, '<a href="' . esc_url( $url ) . '">' . esc_html__( 'Settings', 'lightweight-email-2fa' ) . '</a>' );
	return $links;
}
add_filter( 'plugin_action_links_' . plugin_basename( __FILE__ ), 'lwe2fa_action_links' );

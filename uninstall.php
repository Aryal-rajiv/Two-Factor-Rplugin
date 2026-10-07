<?php
/**
 * Remove all plugin data on uninstall.
 *
 * @package Lightweight_Email_2FA
 */

defined( 'WP_UNINSTALL_PLUGIN' ) || exit;

delete_option( 'lwe2fa_settings' );

foreach ( array( 'lwe2fa_enabled', 'lwe2fa_pending', 'lwe2fa_lockout' ) as $lwe2fa_meta_key ) {
	delete_metadata( 'user', 0, $lwe2fa_meta_key, '', true );
}

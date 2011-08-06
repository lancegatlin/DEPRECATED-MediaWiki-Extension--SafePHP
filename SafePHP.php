<?php
/**
 * SafePHP - Allows safe use of user php script
 *
 * To activate this extension, add the following into your LocalSettings.php file:
 * require_once('$IP/extensions/SafePHP/SafePHP.php');
 *
 * @ingroup Extensions
 * @author Lance Gatlin <lance.gatlin@yahoo.com>
 * @version 0.9
 * @link http://www.ti3wiki.org/Extensions:SafePHP
 * @license http://www.gnu.org/copyleft/gpl.html GNU General Public License 2.0 or later
 */
 
/**
 * Protect against register_globals vulnerabilities.
 * This line must be present before any global variable is referenced.
 */
if( !defined( 'MEDIAWIKI' ) ) {
	echo( "This is an extension to the MediaWiki package and cannot be run standalone.\n" );
	die( -1 );
}

require_once(dirname(__FILE__) . '/SafePHP.setup.php');
require_once(dirname(__FILE__) . '/SafePHP.body.php');
require_once(dirname(__FILE__) . '/SafePHPScript.class.php');
$wgExtensionMessagesFiles['SafePHP'] = dirname(__FILE__) . '/SafePHP.i18n.php';

?>
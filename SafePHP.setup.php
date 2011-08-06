<?php

if ( !defined( 'MEDIAWIKI' ) ) {
	die( 'This file is a MediaWiki extension, it is not a valid entry point' );
}

//Avoid unstubbing $wgParser on setHook() too early on modern (1.12+) MW versions, as per r35980
if ( defined( 'MW_SUPPORTS_PARSERFIRSTCALLINIT' ) ) {
	$wgHooks['ParserFirstCallInit'][] = 'wfInitSafePHP';
} else { // Otherwise do things the old fashioned way
	$wgExtensionFunctions[] = 'wfInitSafePHP';
}

/* register parser hook */
$wgExtensionCredits['parserhook'][] = array(
    'name' => 'SafePHP',
    'author' => 'Lance Gatlin',
    'version' => '0.9',
	'url' => 'http://ti3wiki.org/index.php?title=Extensions:SafePHP',
	'description' => 'Allows for safely executing user php scripts.',
);

$gSafePHP_IP = dirname(__FILE__); //global that tells SafePHP where to write the log

$wgHooks['LanguageGetMagic'][]       = 'SafePHP_Function_Magic';
function SafePHP_Function_Magic( &$magicWords, $langCode ) {
        # Add the magic word
        # The first array element is case sensitive, in this case it is not case sensitive
        # All remaining elements are synonyms for our parser function
        $magicWords['php'] = array( 0, 'php' );
        # unless we return true, other parser functions extensions won't get loaded.
        return true;
}

function wfInitSafePHP() {
    global $wgParser
			,$gSafePHP_LoadedScripts;

	// Hook to for rending caching content
	$wgParser->setHook( 'php', 'SafePHP_TagPHPHook' );
    $wgParser->setFunctionHook( 'php', 'SafePHP_ParserFunctionPHPHook' );

	$gSafePHP_LoadedScripts = array();
	
	SafePHPScript::initGlobals();
	SafePHPScript::$onPossibleAbuseHook[] = 'SafePHP_LogPossibleAbuseAttempt';
}


?>
<?php

function SafePHP_LogPossibleAbuseAttempt($parseErrors, $content)
{
	global $wgUser, $gSafePHP_IP, $wgParser;

	$timestamp = date('YmdGis');
	
	$user = $wgUser->getName();
	
	$out .= "SafePHP: Possible PHP code abuse\n";

	$owner = 'Unknown';
	
	$title = $wgParser->getTitle();
	if($title != null)
		$r = Revision::newFromTitle($title);
	else
		$out .= "SafePHP: Unable to fetch title\n";
		
	if($r != null)
	{
		$owner = $r->getRawUserText();
		$revisionText = $r->getRawText();
	}
	else
		$out .= "SafePHP: Unable to fetch revision\n";

	$out .= "SafePHP: PHP code rendered by $user\n";
	$out .= "SafePHP: PHP code saved by $owner\n";
	$out .= implode("\n", $parseErrors);
	$out .= "\n";
	$out .= "<revision>\n$revisionText\n</revision>\n";
	
	$tmp = explode("\n", $out);
	$out = '';
	foreach($tmp as $i)
		if(strlen($i) > 0)
			$out .= "$timestamp $i\n";
		
	@file_put_contents("$gSafePHP_IP/SafePHP_PossibleAbuse.log", $out, FILE_APPEND);
}

// the script tag <php> hook
function SafePHP_TagPHPHook($content, $params, &$parser )
{
	global $gSafePHP_LoadedScripts;

	$stripitem = isset($params['stripitem']) ? $params['stripitem'] : false; unset($params['stripitem']);
	$showWhiteList = $params['showwhitelist']; unset($params['showwhitelist']);
	$showParse = $params['showparse']; unset($params['showparse']);
	$showResult = $params['showresult']; unset($params['showresult']);
	$showArgs = $params['showargs']; unset($params['showargs']);
	$onLoadFunction = $params['onload']; unset($params['onload']);
	$scriptId = isset($params['id']) ? $params['id'] : md5($content); unset($params['id']);
	
	if($showWhiteList)
		$retv .= '<pre>' . htmlentities(print_r(array('functionWhitelist' => SafePHPScript::$functionWhitelist),true)) . '</pre>';
		
	// script hasn't been encoutered yet?
	if(!array_key_exists($scriptId, $gSafePHP_LoadedScripts))
	{
		// first time encountering script
		$script = new SafePHPScript($scriptId, $content);

		list($parseTokens, $parseErrors) = $script->parse($parser);

		$gSafePHP_LoadedScripts[$scriptId] = true;

		if($showParse)
			$retv .= '<pre>' . htmlentities(print_r(array('parseTokens' => $parseTokens, 'functionsDeclared' => $script->functionsDeclared),true)) . '</pre>';
		
		if(count($parseErrors)>0)
			$retv .= implode("\n\n", $parseErrors) . "\n\n";
		
		// script won't execute if parse failed
		$loadErrors = $script->load();
		if(count($loadErrors)>0)
			$retv .= implode("\n\n", $loadErrors) . "\n\n";
		
		if(strlen($onLoadFunction) > 0)
		{
			list($result, $callErrors) = SafePHPScript::callPHP($onLoadFunction, array(), $showArgs, $showResult, false);

			$retv .= implode("\n\n", $callErrors);
			$retv .= $result;
		}
	}
	
	$retv = $parser->recursiveTagParse($retv);
	
    if($stripitem)
      return $parser->insertStripItem( $retv, $parser->mStripState );
	  
	return $retv;
}

// parse up the template arguments passed to the parsing function
// turn them from 0 => "Key=Value" 
// into 'key' => 'value'
// fixed issue with passing values that have = in them
function SafePHP_getParamsFromParserFunctionHook($args)
{
	$params = array();
	
	if(!is_array($args))
		return $params;
		
	array_shift($args); // remove parser object
	foreach($args as $arg)
	{
		/*
		$a = explode('=',$arg);
		
		if(count($a) == 2)
			$params[$a[0]] = $a[1];
		else
			$params[] = $arg;
		*/
		$split_at = strpos($arg, '=');
		if($split_at === false)
			$params[] = $arg;
		else
			$params[substr($arg,0,$split_at)] = substr($arg, $split_at+1);
	}
	return $params;
}

// the {{#php:}} hook
function SafePHP_ParserFunctionPHPHook(&$parser)
{
	//$retv .= '<pre>' . htmlentities(print_r(array_shift(func_get_args()), true)) . '</pre>';
	$params = SafePHP_getParamsFromParserFunctionHook(func_get_args());
	
	//$retv .= '<pre>' . htmlentities(print_r($params, true)) . '</pre>';
	$func = $params[0];
	array_shift($params); // remove function string from arguments
	//$retv .= '<pre>' . htmlentities(print_r($params, true)) . '</pre>';
	
	$passTemplateArgs = isset($params['passtemplateargs']) ? $params['passtemplateargs'] : true; unset($params['passtemplateargs']);

	// Combines into the parameters the current template arguments
	if($passTemplateArgs && count($parser->mArgStack)>0)
		$params = end($parser->mArgStack) + $params;

	$showResult = $params['showresult']; unset($params['showresult']);
	$showArgs = $params['showargs']; unset($params['showargs']);
	$mapNamedArgs = isset($params['mapnamedargs']) ? $params['mapnamedargs'] : true; unset($params['mapnamedargs']);

// Removed for safety
//	$isHTML = isset($params['isHTML']) ? $params['isHTML'] : false; unset($params['isHTML']);
//	$noparse = isset($params['noparse']) ? $params['noparse'] : false; unset($params['noparse']);
	$noparse = false; $isHTML = false;
	
	$stripitem = isset($params['stripitem']) ? $params['stripitem'] : false; unset($params['stripitem']);
	
	list($result, $callErrors) = SafePHPScript::callPHP($func, $params, $showArgs, $showResult, $mapNamedArgs);
	
	$retv .= implode("\n\n", $callErrors);
	$retv .= $result;
	
    if($stripitem)
      return $parser->insertStripItem( $parser->recursiveTagParse($retv), $parser->mStripState );
    
    return array( $retv, 'noparse' => $noparse, 'isHTML' => $isHTML);
}

?>
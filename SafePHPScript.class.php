<?php
/**
 * SafePHPScript - Pre-parsers user php script for safety, loads the script and then allows calling
 * the functions declared with named argument mapping. Though once loaded, functions can be invoked
 * by normal PHP call methods.
 *
 * @ingroup Extensions
 * @author Lance Gatlin <lance.gatlin@yahoo.com>
 * @version 0.9
 * @link http://www.ti3wiki.org/Extension:SafePHP
 * @license http://www.gnu.org/copyleft/gpl.html GNU General Public License 2.0 or later
 */

$gSafePHPScript_IP = dirname(__FILE__); // global where SafePHPScript looks for whitelist & blacklist files

define('SAFEPHPSCRIPT_SCOPE_GLOBAL', 0);
define('SAFEPHPSCRIPT_SCOPE_FUNCTION', 1);
define('SAFEPHPSCRIPT_SCOPE_DECLAREFUNCTION', 2);
define('SAFEPHPSCRIPT_SCOPE_DECLAREFUNCTIONARGUMENTS', 3);
define('SAFEPHPSCRIPT_SCOPE_DECLAREGLOBALS', 4);

class SafePHPScript 
{
	static $globalsInitd = false
			,$functionWhitelist
			,$functionBlacklist
			,$tokenBlacklist
			,$superglobalBlacklist
			,$globalWhitelist
			,$customFunctions
			,$onPossibleAbuseHook
			;
	
	static function initGlobals()
	{
		global $gSafePHPScript_IP;
		
		if(SafePHPScript::$globalsInitd == true)
			return;
			
		$globalsInitd = true;
		
		// get the function whitelist
		$funcWhitelist = explode("\n", file_get_contents("$gSafePHPScript_IP/SafePHP_Whitelist.txt"));
		foreach($funcWhitelist as $i)
			SafePHPScript::$functionWhitelist[trim($i)] = true;

		// get the function blacklist
		$funcBlacklist = explode("\n", file_get_contents("$gSafePHPScript_IP/SafePHP_Blacklist.txt"));
		foreach($funcBlacklist as $i)
			SafePHPScript::$functionBlacklist[trim($i)] = true;
		
		// get the superglobals list
		$superGlobals = array (
			'$GLOBALS'
			,'$_SERVER'
			,'$_GET' 
			,'$_POST'
			,'$_FILES'
			,'$_COOKIE'
			,'$_SESSION'
			,'$_REQUEST'
			,'$_ENV'
		);
		foreach($superGlobals as $i)
			SafePHPScript::$superglobalBlacklist[$i] = true;
			
		// get the token blacklist
		$tokenBlacklist = array (
			T_ABSTRACT	//abstract	Class Abstraction (available since PHP 5.0.0)
			//T_AND_EQUAL	&=	assignment operators
			//T_ARRAY	array()	array(), array syntax
			//T_ARRAY_CAST	(array)	type-casting
			//T_AS	as	foreach
			,T_BAD_CHARACTER	 	//anything below ASCII 32 except \t (0x09), \n (0x0a) and \r (0x0d)
			//T_BOOLEAN_AND	&&	logical operators
			//T_BOOLEAN_OR	||	logical operators
			//T_BOOL_CAST	(bool) or (boolean)	type-casting
			//T_BREAK	break	break
			//T_CASE	case	switch
			,T_CATCH	//catch	Exceptions (available since PHP 5.0.0)
			//T_CHARACTER	 	 
			,T_CLASS	//class	classes and objects
			,T_CLASS_C	//__CLASS__	magic constants (available since PHP 4.3.0)
			,T_CLONE	//clone	classes and objects (available since PHP 5.0.0)
			,T_CLOSE_TAG	// ? > or % >	 
			//T_COMMENT	// or #, and /*  */ in PHP 5	comments
			//T_CONCAT_EQUAL	.=	assignment operators
			//T_CONST	const	 
			//T_CONSTANT_ENCAPSED_STRING	"foo" or 'bar'	string syntax
			//T_CONTINUE	continue	 
			,T_CURLY_OPEN	 	 
			//T_DEC	--	incrementing/decrementing operators
			,T_DECLARE 	//declare	declare
			//T_DEFAULT	default	switch
			,T_DIR	//__DIR__	magic constants (available since PHP 5.3.0)
			//T_DIV_EQUAL	/=	assignment operators
			//T_DNUMBER	0.12, etc	floating point numbers
			//T_DOC_COMMENT	/** */	PHPDoc style comments (available since PHP 5.0.0)
			//T_DO	ndo	do..while
			//T_DOLLAR_OPEN_CURLY_BRACES	${	complex variable parsed syntax
			//T_DOUBLE_ARROW	=>	array syntax
			//T_DOUBLE_CAST	(real), (double) or (float)	type-casting
			//T_DOUBLE_COLON	::	see T_PAAMAYIM_NEKUDOTAYIM below
			,T_ECHO	//echo	echo()
			//T_ELSE	else	else
			//T_ELSEIF	elseif	elseif
			//T_EMPTY	empty	empty()
			//T_ENCAPSED_AND_WHITESPACE	 	 
			,T_ENDDECLARE	//enddeclare	declare, alternative syntax
			//T_ENDFOR	endfor	for, alternative syntax
			//T_ENDFOREACH	endforeach	foreach, alternative syntax
			//T_ENDIF	endif	if, alternative syntax
			//T_ENDSWITCH	endswitch	switch, alternative syntax
			//T_ENDWHILE	endwhile	while, alternative syntax
			//T_END_HEREDOC	 	heredoc syntax
			,T_EVAL	//eval()	eval()
			//T_EXIT	exit or die	exit(), die()
			,T_EXTENDS	//extends	extends, classes and objects
			,T_FILE	//__FILE__	magic constants
			,T_FINAL	//final	Final Keyword (available since PHP 5.0.0)
			//T_FOR	for	for
			//T_FOREACH	foreach	foreach
			//T_FUNCTION	//function or cfunction	functions
			,T_FUNC_C	//__FUNCTION__	magic constants (available since PHP 4.3.0)
			//T_GLOBAL	//global	variable scope
			,T_GOTO	//goto	undocumented (available since PHP 5.3.0)
			,T_HALT_COMPILER	//__halt_compiler()	__halt_compiler (available since PHP 5.1.0)
			//T_IF	if	if
			,T_IMPLEMENTS	//implements	Object Interfaces (available since PHP 5.0.0)
			//T_INC	++	incrementing/decrementing operators
			,T_INCLUDE	//include()	include()
			,T_INCLUDE_ONCE	//include_once()	include_once()
			,T_INLINE_HTML	 	 
			//T_INSTANCEOF	instanceof	type operators (available since PHP 5.0.0)
			//T_INT_CAST	(int) or (integer)	type-casting
			,T_INTERFACE	//interface	Object Interfaces (available since PHP 5.0.0)
			//T_ISSET	isset()	isset()
			//T_IS_EQUAL	==	comparison operators
			//T_IS_GREATER_OR_EQUAL	>=	comparison operators
			//T_IS_IDENTICAL	===	comparison operators
			//T_IS_NOT_EQUAL	!= or <>	comparison operators
			//T_IS_NOT_IDENTICAL	!==	comparison operators
			//T_IS_SMALLER_OR_EQUAL	<=	comparison operators
			,T_LINE	//__LINE__	magic constants
			//T_LIST	list()	list()
			//T_LNUMBER	123, 012, 0x1ac, etc	integers
			//T_LOGICAL_AND	and	logical operators
			//T_LOGICAL_OR	or	logical operators
			//T_LOGICAL_XOR	xor	logical operators
			,T_METHOD_C	//__METHOD__	magic constants (available since PHP 5.0.0)
			//T_MINUS_EQUAL	-=	assignment operators
			//T_ML_COMMENT	/* and */	comments (PHP 4 only)
			//T_MOD_EQUAL	%=	assignment operators
			//T_MUL_EQUAL	*=	assignment operators
			,T_NS_C	//__NAMESPACE__	namespaces. Also defined as T_NAMESPACE (available since PHP 5.3.0)
			,T_NEW	//new	classes and objects
			//T_NUM_STRING	 	 
			,T_OBJECT_CAST	//(object)	type-casting
			,T_OBJECT_OPERATOR	//->	classes and objects
			,T_OLD_FUNCTION	//old_function	 
			//T_OPEN_TAG	//< ?php, < ? or < %	escaping from HTML
			,T_OPEN_TAG_WITH_ECHO	// < ?= or < %=	escaping from HTML
			//T_OR_EQUAL	// |=	assignment operators
			,T_PAAMAYIM_NEKUDOTAYIM	//::	::. Also defined as T_DOUBLE_COLON.
			//T_PLUS_EQUAL	//+=	assignment operators
			,T_PRINT	//print()	print()
			,T_PRIVATE	//private	classes and objects (available since PHP 5.0.0)
			,T_PUBLIC	//public	classes and objects (available since PHP 5.0.0)
			,T_PROTECTED	//protected	classes and objects (available since PHP 5.0.0)
			,T_REQUIRE	//require()	require()
			,T_REQUIRE_ONCE	//require_once()	require_once()
			//T_RETURN	return	returning values
			//T_SL	<<	bitwise operators
			//T_SL_EQUAL	<<=	assignment operators
			//T_SR	>>	bitwise operators
			//T_SR_EQUAL	>>=	assignment operators
			,T_START_HEREDOC	//<<<	heredoc syntax
			//T_STATIC	//static	variable scope
			//T_STRING	 	 
			//T_STRING_CAST	(string)	type-casting
			//T_STRING_VARNAME	 	 
			//T_SWITCH	switch	switch
			,T_THROW	//throw	Exceptions (available since PHP 5.0.0)
			,T_TRY	//try	Exceptions (available since PHP 5.0.0)
			//T_UNSET	unset()	unset()
			//T_UNSET_CAST	(unset)	type-casting (available since PHP 5.0.0)
			,T_USE	//use	namespaces (available since PHP 5.3.0)
			//T_VAR	var	classes and objects
			//T_VARIABLE	$foo	variables
			//T_WHILE	while	while, do..while
			//T_WHITESPACE	 	 
			//T_XOR_EQUAL	^=	assignment operators		
		);
		foreach($tokenBlacklist as $i)
			SafePHPScript::$tokenBlacklist[$i] = true;
			
		SafePHPScript::$globalWhitelist = array();
		SafePHPScript::$customFunctions = array();
		SafePHPScript::$onPossibleAbuseHook = array();
	}
	
	// script info
	var $id, $content, $parseOk, $functionsDeclared, $parseErrors;
	
	// parsing state
	var $parseTokens
		,$lastToken
		,$argCount
		,$currentFunction
		,$scopeStack
		,$bracketNestCount
		,$openTagCount;
	
	function __construct($id, $content)
	{
		$this->id = $id;
		$this->content = $content;
		$this->clearParseState();
	}
	
	// parse the script
	// returns an array(parseErrors, parseTokens)
	function parse()
	{
		$this->clearParseState();
		
		// parse content into tokens
		$this->tokens = token_get_all('<?'.'php '.$this->content);	
		
		// iterate through tokens to make sure code is safe
		foreach ($this->tokens as $token) 
		{
			if(is_array($token))
			{
				list($id, $string, $linenumber) = $token;
		
				$this->parseTokens[] = array('id' => token_name($id), 'string' => htmlentities($string), 'line' => $linenumber, 'scope' => $this->getScopeString());

				// token is disallowed?
				if(array_key_exists($id, SafePHPScript::$tokenBlacklist))
				{
					$this->parseFatalError($linenumber,token_name($id) . ' not allowed.');
					break; // Fatal error quit parsing
				}
				
				switch($id)
				{
					// ignore white space and comments
					case T_WHITESPACE :
					case T_COMMENTS :
						continue 2;
						
					case T_DOLLAR_OPEN_CURLY_BRACES: // for strings with ${ embedded
						++$this->bracketNestCount;
						break;
					case T_OPEN_TAG:
						// only one of these allowed -- and its inserted above
						if(++$this->openTagCount > 1)
						{
							// can't actually get here? parser doesnt reccognize < ? php if ? > doesnt occur
							$this->parseFatalError($linenumber, 'T_OPEN_TAG not allowed.');
							break 2; // Fatal error quit parsing
						}
						continue 2; // ignore the first open tag
				}
				
			}
			else
			{
				$this->parseTokens[] = array('char' => $token, 'scope' => $this->getScopeString());
				$id = null; $string = null; // linenumber preserved since no linenumber provided for chars from tokenizers
				
				switch($token)
				{
					case '`':
						// backtick operator
						$this->parseFatalError($linenumber, 'backtick operator not allowed.');
						break 2; // Fatal error quit parsing
					case '{' :
						++$this->bracketNestCount;
						break;
					case '}' :
						--$this->bracketNestCount;
						break;
				}
			}	
			
			switch($this->getScope())
			{
				case SAFFEPHP_SCOPE_GLOBAL :
					$noFatalError = $this->parseHandleGlobalScopeToken($token, $id, $string, $linenumber);
					break;
				case SAFEPHPSCRIPT_SCOPE_FUNCTION :
					$noFatalError = $this->parseHandleFunctionScopeToken($token, $id, $string, $linenumber);
					break;
				case SAFEPHPSCRIPT_SCOPE_DECLAREFUNCTION :
					$noFatalError = $this->parseHandleDeclareFunctionScopeToken($token, $id, $string, $linenumber);
					break;
				case SAFEPHPSCRIPT_SCOPE_DECLAREFUNCTIONARGUMENTS :
					$noFatalError = $this->parseHandleDeclareFunctionArgumentsScopeToken($token, $id, $string, $linenumber);
					break;
				case SAFEPHPSCRIPT_SCOPE_DECLAREGLOBALS :
					$noFatalError = $this->parseHandleDeclareGlobalsScopeToken($token, $id, $string, $linenumber);
					break;
				default:
					$this->parseFatalError($linenumber, 'internal parser error.');
					$noFatalError = false;
					break;
			}
			
			// fatal error?
			if(!$noFatalError)
			{
				$this->parseError($linenumber, 'fatal error encountered, parsing stopped.');
				break;
			};
				
			$this->lastToken = $token;
		}
		
		$this->parseOk = (count($this->parseErrors) == 0);
		if($this->parseOk)
		{
			// make custom functions available for execution
			foreach($this->functionsDeclared as $name => $args)
				// add it to the custom function list
				SafePHPScript::$customFunctions[$name] = $args;
		}
		
		return array($this->parseTokens, $this->parseErrors);
	}
	
	// Attempts to load the script (runs eval)
	// Fails if script hasn't been successfully parsed first
	// Returns empty string on success
	// Returns a string error message on failure
	function load()
	{
		$retv = array();
		
		if($this->parseOk)
		{
			ob_start();
			eval($this->content);
			$errorOutput = trim(ob_get_contents());
			ob_end_clean();
			if(strlen($errorOutput)>0)
			{
				$this->parseOk = false;
				$retv[] = 'SafePHPScript Load Error->Id[' . $this->id . "]:\n";
				$retv[] = $errorOutput;
			}
		}
		else
			$retv[] = 'SafePHPScript Load Error->Id[' . $this->id . ']: parse failed script not loaded.';
		
		return $retv;
	}

	// returns array( $text_from_function, $errorArray )
	static function callPHP($func, $params = array(), $showArgs = false, $showResult = false, $mapNamedArgs = true)
	{
		$errors = array();
		$retv = null;
		
		// function blacklisted?
		if(array_key_exists($func, SafePHPScript::$functionBlacklist))
		{
			$errors[] = "SafePHP Error: function $func not allowed.";
			SafePHPScript::PossibleAbuseAttempt(array($retv), $func);
			return array($retv, $errors);
		}
		// function whitelisted and is callable?
		if(!is_callable($func))
		{
			$errors[] = "SafePHP Error: function $func does not exist (or there are errors in the script).";
			return array($retv, $errors);
		}
		if(!array_key_exists($func, SafePHPScript::$functionWhitelist))
		{
			$errors[] = "SafePHP Error: function $func not allowed.";
			return array($retv, $errors);
		}
			
		// reorder numeric arguments in case it starts with 1
		$params = array_merge($params);
		
		$fArgs = SafePHPScript::$customFunctions[$func];
  
		if($fArgs != null && $mapNamedArgs)
		{
			// custom function
			
			// add a parameter for getting the arguments array
			// if a function wants the argument array they just 
			// declare a parameter args
			if(!array_key_exists('args', $params))
				$params['args'] = $params;
				
			// map named arguments as declared by function
			// to the corresponding argument position
			// if it is a named argument in params
			// if it is missing from params
			// then fill it with the numeric index from params
			$indexArg = 0;
			foreach($fArgs as $arg => $index)
			{
				if(array_key_exists($arg, $params))
					$args[$index] = $params[$arg];
				elseif(array_key_exists($indexArg, $params))
					$args[$index] = $params[$indexArg++];
			}
			  
		}
		else
			// hopefully user knows what they are doing with this
			// only numeric arguments (non-named) will matter to call_user_func
			// any named arguments will be discarded
			$args = $params;

		if($showArgs)
			$retv .= '<pre>' . htmlentities(print_r(array('args' => $args),true)) . '</pre>';
			
		try {
			// catch syntax errors in script that aren't detected until runtime
			ob_start();
			$result = call_user_func_array($func, $args);
			$errorOutput = trim(ob_get_contents());
			ob_end_clean();
			if(strlen($errorOutput)>0)
				$errors[] = 'SafePHP Runtime Error->Func[' . $func . "]:" . $errorOutput;
		} 
		catch(Exception $e)
		{
			$errors .= 'SafePHP Exception->Func[' . $func . ']: ' . $e->getMessage();
			return array($retv, $errors);
		}
		
		if(is_object($result))
			$result = 'Object';
		elseif(is_array($result))
			$result = implode(',', $result);

		if(strlen($result)>0)
		{
			if($showResult)
				$retv .= '<pre>' . htmlentities(print_r(array('result' => $result),true)) . '</pre>';

			$retv .= $result;
		}
			
		return array($retv, $errors);
	}

	// Private helper functions
	
	function getScope() { return end($this->scopeStack); }
	function getScopeString() 
	{ 
		switch($this->getScope())
		{
			case SAFEPHPSCRIPT_SCOPE_GLOBAL: return 'global';
			case SAFEPHPSCRIPT_SCOPE_FUNCTION: return 'function';
			case SAFEPHPSCRIPT_SCOPE_DECLAREFUNCTION: return 'declare_function';
			case SAFEPHPSCRIPT_SCOPE_DECLAREFUNCTIONARGUMENTS: return 'declare_function_arguments';
			case SAFEPHPSCRIPT_SCOPE_DECLAREGLOBALS: return 'declare_global_variables';
		}
		return 'error';
	}
	function enterScope($scope) { array_push($this->scopeStack, $scope); }
	function exitScope() { array_pop($this->scopeStack); }
	
	static function PossibleAbuseAttempt($parseErrors, $content)
	{
		foreach(SafePHPScript::$onPossibleAbuseHook as $k => $funct)
			call_user_func($funct, $parseErrors, $content);
	}
	
	function parseError($linenumber, $msg)
	{
		$this->parseErrors[] = 'SafePHP Error->Line[' . $linenumber . ']: ' . $msg;
		return true;
	}
	
	function parseFatalError($linenumber, $msg)
	{
		$this->parseError($linenumber, $msg);
		SafePHPScript::PossibleAbuseAttempt($this->parseErrors, $this->content);
		return false;
	}

	function clearParseState()
	{
		$this->parseOk = false;
		$this->parseErrors = array();
		$this->parseTokens = array();
		$this->lastToken = null;
		$this->currentFunction = null;
		$this->argCount = 0;
		$this->scopeStack = array();
		$this->enterScope(SAFEPHPSCRIPT_SCOPE_GLOBAL);
		$this->bracketNestCount = 0;
		$this->openTagCount = 0;
		$this->functionsDeclared = array();
	}
	
	function parseHandleGlobalScopeToken($token, $id, $string, $linenumber)
	{

		switch($id)
		{
			case T_FUNCTION:
				$this->enterScope(SAFEPHPSCRIPT_SCOPE_DECLAREFUNCTION);
				return true;
			
		}
		
		return $this->parseFatalError($linenumber, ($id != null ? token_name($id) : "'$token'") . ' not allowed at global scope. (place within a function).');
	}
			
	function parseHandleFunctionScopeToken($token, $id, $string, $linenumber)
	{
		// allow normal parsing within function scope
		// token is array? (array = parsed token)
			
		switch($id)
		{
			// nest functions disallowed
			case T_FUNCTION:
				return $this->parseFatalError($linenumber, 'function nesting not allowed.');
				
			// variable encountered
			case T_VARIABLE:
				// superglobals disallowed
				if(array_key_exists($string, SafePHPScript::$superglobalBlacklist))
					return $this->parseFatalError($linenumber, $string . ' superglobal not allowed.');
				break;
			
			// global keyword 
			case T_GLOBAL:
				$this->enterScope(SAFEPHPSCRIPT_SCOPE_DECLAREGLOBALS);
				break;
				
			// token is a character
			default:
				switch($token)
				{
					// function finished
					case '}' : 
						if($this->bracketNestCount == 0)
							$this->exitScope();
						break;
					case '(' :
						// function call? might also be array, if, switch (other things?)
						list($lastTokenId,$lastTokenStr,$lastTokenLn) = $this->lastToken;
						
						// look at the last token to determine function name and if function is allowed
						if($lastTokenId == T_STRING)
						{
							// function call
							
							// function blacklisted?
							if(array_key_exists($lastTokenStr, SafePHPScript::$functionBlacklist))
								return $this->parseFatalError($lastTokenLn, $lastTokenStr . ' function not allowed.');
							// function whitelisted?
							elseif(!array_key_exists($lastTokenStr, SafePHPScript::$functionWhitelist))
								$this->parseError($lastTokenLn, $lastTokenStr . ' function not allowed.');
						}
						break;						
				}
		}
		return true;
	}
	
	function parseHandleDeclareFunctionScopeToken($token, $id, $string, $linenumber)
	{
		switch($id)
		{
			case T_STRING :
				$funcName = $string;
				
				if(function_exists($funcName))
					$this->parseError($linenumber, $funcName . ' function already exists.');
				else
				{
					// function already declared?
					if(!isset($functionsDeclared[$funcName]))
					{
						// add it to the white list
						SafePHPScript::$functionWhitelist[$funcName] = true;
						// add it the list of functions declared
						$this->functionsDeclared[$funcName] = array();
						$this->currentFunction = &$this->functionsDeclared[$funcName];
					}
					else
						$this->parseError($linenumber, $funcName . ' function already declared.');
				}
				break;
			
			// token is character
			default:
				switch($token)
				{
					case '(' :
						$this->exitScope();
						$this->enterScope(SAFEPHPSCRIPT_SCOPE_DECLAREFUNCTIONARGUMENTS);
						break;
				}
		}
		return true;
	}
	
	function parseHandleDeclareFunctionArgumentsScopeToken($token, $id, $string, $linenumber)
	{
		switch($id)
		{
			case T_VARIABLE :
				// add the variable declaration to the list of function arguments
				// remove $ from $var for variable name
				// and store the index of the variable for later mapping
				$this->currentFunction[substr($string,1)] = $this->argCount++;
				break;
			// token is character
			default:
				switch($token)
				{
					case ')' : 
						$this->argCount = 0;
						$this->exitScope();
						$this->enterScope(SAFEPHPSCRIPT_SCOPE_FUNCTION);
						break;
				}
		}
		return true;
	}
	
	function parseHandleDeclareGlobalsScopeToken($token, $id, $string, $linenumber)
	{
		switch($id)
		{
			case T_VARIABLE :
				// global doesn't exist? (remove $ from beginning of string)
				if(!isset($GLOBALS[substr($string,1)]))
					SafePHPScript::$globalWhitelist[$string] = true;
				// global is whitelisted?
				elseif(!array_key_exists($string, SafePHPScript::$globalWhitelist))
					return $this->parseFatalError($linenumber, $string . ' global not allowed.');
			break;
			// token is character
			default:
				switch($token)
				{
					case ';' : 
						$this->exitScope();
						break;
				}
		}
		return true;
	}
};

?>
<?php namespace magic3w\phpauth\sdk;

use Exception;

class Token
{
	
	private $sso;
	private $token;
	private $expires;
	
	public function __construct($sso, $token, $expires) {
		$this->sso = $sso;
		$this->token = $token;
		$this->expires = $expires;
	}
	
	public function getId() {
		return $this->token;
	}
	
	public function getTokenInfo() {
		static $cache = null;
		
		if ($cache !== null) { return $cache; }
		
		$response = file_get_contents($this->sso->getEndpoint() . '/auth/index/' . $this->token . '.json');
		
		if (!isset($http_response_header))            { throw new Exception('SSO connection failed'); }
		if (!strstr($http_response_header[0], '200')) { throw new Exception('SSO error'); }
		
		return $cache = json_decode($response);
	}
	
	public function isAuthenticated() {
		return $this->getTokenInfo()->authenticated;
	}
}

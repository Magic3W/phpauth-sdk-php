<?php namespace magic3w\phpauth\sdk;

use \Lcobucci\JWT\Token\RegisteredClaims;

class Token
{
	
	/**
	 * 
	 * @var SSO
	 */
	private $sso;
	
	/**
	 * 
	 * @var string
	 */
	private $token;
	
	/**
	 * 
	 * @var int
	 */
	private $expires;
	
	public function __construct(SSO $sso, \Lcobucci\JWT\Token $token, int $expires) {
		$this->sso = $sso;
		$this->token = $token;
		$this->expires = $expires;
	}
	
	/**
	 * Returns the token's ID
	 * 
	 * @return string
	 */
	public function getId() {
		return $this->token;
	}
	
	/**
	 * Indicates whether the session was expired, or whether the session is still active.
	 * 
	 * @return bool
	 */
	public function isExpired() : bool
	{
		return time() > $this->expires;
	}
	
	public function isAuthenticated() {
		return $this->expires > time();
	}
	
	/**
	 * Returns the audience for this token. If the token is not issued to this application
	 * we should fail it. This is generally the case because we will rarely use this SDK
	 * to handle tokens that were not signed for us and have a different audience than us.
	 * 
	 * @return int The app id of the audience.
	 */
	public function audience() 
	{
		/**
		 * We know that the token can only have one audience. So we use the first item of the
		 * claims array.
		 */
		return reset($this->token->claims->get(RegisteredClaims::AUDIENCE, []));
	}
	
	/**
	 * This is the client the token was issued to. This means that, this application
	 * is to be blamed for any changes or requests made using this token.
	 * 
	 * The application has been properly authenticated by using it's client credentials
	 * to ensure this token was valid.
	 * 
	 * To do this we're using the non-standard claim `for`, which indicates that the token
	 * is issued to be used by this application.
	 * 
	 * @return int The app id of the client attemptin to access the data
	 */
	public function client () 
	{
		/**
		 * We know that the token can only have one issuing client. So we use the first item of the
		 * claims array.
		 */
		return reset($this->token->claims->get(RegisteredClaims::ISSUER, []));
	}
}

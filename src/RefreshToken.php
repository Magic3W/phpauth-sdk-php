<?php namespace magic3w\phpauth\sdk;

use magic3w\http\url\reflection\URLReflection;
use spitfire\io\request\Request;

class RefreshToken
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
	 * @var int|null
	 */
	private $expires;
	
	/**
	 * 
	 * @param SSO $sso
	 * @param string $token
	 * @param int|null $expires
	 */
	public function __construct(SSO $sso, string $token, int $expires = null) 
	{
		$this->sso = $sso;
		$this->token = $token;
		$this->expires = $expires;
	}
	
	/**
	 * 
	 * @return string
	 */
	public function getId() {
		return $this->token;
	}
	
	/**
	 * The renew method 
	 * 
	 * @return array{'access': Token, 'refresh': RefreshToken}
	 */
	public function renew() : array
	{	
		$request = new Request(sprintf('%s/token/create.json', $this->sso->getEndpoint()));
		$request->post('type', 'refresh_token');
		$request->post('token', $this->token);
		$request->post('client', (string)$this->sso->getAppId());
		$request->post('secret', $this->sso->getSecret());
		$response = $request->send()->expect(200)->json();
		
		return [
			'access'  => new Token($this->sso, $response->tokens->access->token, $response->tokens->access->expires),
			'refresh' => new RefreshToken($this->sso, $response->tokens->refresh->token, $response->tokens->refresh->expires)
		];
	}
	
	/**
	 * Indicates whether the session was expired, or whether the session is still active.
	 * 
	 * Please note that PHPAS expires refresh tokens after (usually) 2 years to make sure that
	 * the tokens can't be abused in the wild. But it's possible that this endpoint returns 
	 * false negatives for tokens that were expired for other reasons than just their age.
	 * 
	 * Among those reasons could be things like:
	 * 
	 *  - Security breaches and credential expirations / renewals
	 *  - Maintenance to free resources
	 * 
	 * In these cases, the renew method will fail and you will be required to reach out to the
	 * user to request a reauthentication.
	 * 
	 * @return bool
	 */
	public function isExpired() : bool
	{
		return time() > $this->expires;
	}
	
}

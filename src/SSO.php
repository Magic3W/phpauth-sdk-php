<?php namespace magic3w\phpauth\sdk;

use CURLFile;
use Exception;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Lcobucci\JWT\Signer\Key\InMemory;
Use spitfire\io\request\Request;
use magic3w\http\url\reflection\URLReflection;

class SSO
{
	
	private $endpoint;
	private $appId;
	private $appSecret;
	
	private $jwt;
	
	public function __construct($credentials) {
		$reflection = URLReflection::fromURL($credentials);
		
		$this->endpoint  = rtrim($reflection->getProtocol() . '://' . $reflection->getServer() . ':' . $reflection->getPort() . $reflection->getPath(), '/');
		$this->appId     = $reflection->getUser();
		$this->appSecret = $reflection->getPassword();
		
		if (!$this->appSecret) {
			throw new Exception('App Secret is missing', 1807021658);
		}
		
		$this->jwt = Configuration::forSymmetricSigner(new Sha256, InMemory::base64Encoded($this->appSecret));
	}

	/**
	 * Generates a URL to direct the user agent to in order to initiate
	 * the authentication. Please note that the oAuth 2.0 protocol uses the user
	 * agent for this 'request', therefore the server itself is not performing 
	 * the request at all.
	 * 
	 * I would like to avoid using the word request for whatever is happening
	 * at this stage of the connection.
	 * 
	 * @param string $host The app ID of the application this client wishes to access data from. This may
	 *        be null if the application wishes to access the client account on PHPAS.
	 * 
	 * @todo Include a target in the access code request so we can request a token for another app
	 * @return string
	 */
	public function makeAccessCodeRedirect($state, $verifier_challenge, $returnto, $audience = null) {
		
		$request = URLReflection::fromURL(sprintf('%s/auth/oauth', $this->endpoint));
		$request->get('response_type', 'code');
		$request->get('client', $this->appId);
		$request->get('state', $state);
		$audience && $request->get('audience', $audience);
		$request->get('redirect', $returnto);
		$request->get('code_challenge', hash('sha256', $verifier_challenge));
		$request->get('code_challenge_method', 'S256');

		return strval($request);
	}
	
	/**
	 * Tokens can be retrieved using three different mechanisms.
	 * 
	 * 1. Provide an access code that a user generated. This is used during the oAuth flow
	 * 2. Provide application specific credentials, yields a client token
	 * 3. Provide a refresh token.
	 * 
	 * This mechanism intends to make it simple for the applications to generate new tokens
	 * for the first scenario, by providing a code and a verifier to the table.
	 */
	public function token($code, $verifier, $audience = null) 
	{
		$request = URLReflection::fromURL(sprintf('%s/token/create.json', $this->endpoint));
		$request->post('code', $code);
		$request->post('type', 'code');
		$request->post('client', $this->sso->getAppId());
		$request->post('secret', $this->sso->getSecret());
		$request->post('verifier', $verifier);
		$audience && $request->post('audience', $audience);
		$response = $request->send()->expect(200)->json();
		
		return [
			'access'  => new Token($this, $this->jwt->parser()->parse($response->tokens->access->token), $response->tokens->access->expires),
			'refresh' => new RefreshToken($this, $response->tokens->refresh->token, $response->tokens->refresh->expires)
		];
	}
	
	/**
	 * Refreshes an access and refresh token by passing a refresh token to the 
	 * system as grant.
	 * 
	 * The token must be a string, if you held onto the `Token` object you received
	 * from the API, you can extract the code by calling getToken.
	 */
	public function refresh(string $token) 
	{
		$token = new RefreshToken($this, $token, null);
		return $token->renew();
	}
	
	/**
	 * Returns an access token that allows the application to access it's own credentials
	 * on the server.
	 * 
	 * @return Token
	 */
	public function credentials($audience = null) 
	{
		$request = URLReflection::fromURL(sprintf('%s/token/create.json', $this->endpoint));
		$request->post('type', 'client_credentials');
		$request->post('client', $this->sso->getAppId());
		$request->post('secret', $this->sso->getSecret());
		$audience && $request->post('audience', $audience);
		$response = $request->send()->expect(200)->json();
		
		return new Token($this, $response->tokens->access->token, $response->tokens->access->expires);
	}
	
	/**
	 * Since the server no longer acts as a hub for user information, this endpoint is deprecated and 
	 * should no longer be used.
	 * 
	 * @deprecated since version 0.1
	 */
	public function getUser($username, Token$token = null) {
		
		if (!$username) { throw new Exception('Valid user id needed'); }
		
		$request = new Request(
			$this->endpoint . '/user/detail/' . $username . '.json',
			$token && $token->isAuthenticated()? Array('token' => $token->getTokenInfo()->token, 'signature' => (string)$this->makeSignature()) : Array('signature' => (string)$this->makeSignature())
		);
		
		/*
		 * Fetch the JSON message from the endpoint. This should tell us whether 
		 * the request was a success.
		 */
		$data = $request->send()->expect(200)->json();
		
		return new User($data->id, $data->username, $data->aliases, $data->groups, $data->verified, $data->registered_unix, $data->attributes, $data->avatar);
	}
	
	/**
	 * @deprecated PHPAS does no longer send email, refer to stat for this.
	 */
	public function sendEmail($userid, $subject, $body) {
		
		$request = new Request(
			$this->endpoint . '/email/send/' . $userid . '.json',
			Array('appId' => $this->appId, 'appSecret' => $this->appSecret)
		);
		
		$request->post('body', $body);
		$request->post('subject', $subject);

		$response = $request->send();
		$data = ($response)->expect(200)->json()->payload;
		
		return $data;
	}
	
	public function getEndpoint() {
		return $this->endpoint;
	}
	
	public function getAppId() {
		return $this->appId;
	}
	
	/**
	 * Returns the secret the system is using to communicate with the server. This can be
	 * used by refresh tokens to renew their lease.
	 * 
	 * @return string
	 */
	public function getSecret() {
		return $this->appSecret;
	}
	
	/**
	 * 
	 * @deprecated The new version of PHPAS allows users to create applications (allowing them to have
	 * as many as they want), which makes the functionality of this method clunky and useless.
	 */
	public function getAppList() {
		$url      = $this->endpoint . '/appdrawer/index.json';
		$request  = new Request($url, ['signature' => (string)$this->makeSignature(), 'all' => 'yes']);
		$data     = $request->send()->expect(200)->json();
		return $data;
	}
	
	/**
	 * 
	 * @deprecated since version 0.1-dev
	 * @return type
	 */
	public function getAppDrawer() {
		$url = $this->endpoint . '/appdrawer/index.json';
		$request  = new Request($url, []);
		
		$response = $request->send()->expect(200)->json();
		
		return $response;
	}
	
	/**
	 * 
	 * @deprecated since version 0.1-dev
	 * @return type
	 */
	public function getAppDrawerJS() {
		return $this->endpoint . '/appdrawer/index.js';
	}
	
	public function getGroupList() {
		$url  = new Request($this->endpoint . '/group/index.json');
		$resp = $url->send()->expect(200)->json();
		
		return $resp->payload;
	}
	
	public function getGroup($id) {
		$url  = new Request($this->endpoint . '/group/detail/' . $id . '.json');
		return $url->send()->expect(200)->json()->payload;
	}
	
	
	/**
	 * This method allows your client to push a custom scope onto the server. This scope
	 * can then be used by third party applications to request access to parts of the user's
	 * data that you requested be fenced off.
	 * 
	 * @param string $id
	 * @param string $name
	 * @param string $description
	 * @param string $icon
	 * @return void
	 */
	public function putScope($id, $name, $description, $icon = null) : void
	{
		$request = new Request(
			sprintf('%s/scope/create/%s.json', $this->getEndpoint(), $id), 
			['token' => (string)$this->credentials()->getId()]
		);
		
		$request->send(['name' => $name, 'description' => $description, 'icon' => new CURLFile($icon)]);
	}
	
	/**
	 * Generate a logout link. The logout flow is best described as follows:
	 * 
	 * 1. Client generates a logout link, which contains a return URL to direct the user to on successful logout
	 * 2. Resource owner is directed to the logout location
	 * 3. Authentication server terminates the session, and all authenticated tokens that depend on it
	 * 4. Authentication directs the resource owner to the return URL
	 * 5. Client destroys the session on their end.
	 * 
	 * Alternatively, the client can execute the 5fth point first.
	 * 
	 * Asynchronously, the Authentication server will start notifying all applications
	 * using tokens in the current session to destroy them. 
	 * 
	 * Invoking this endpoint is optional, it only ends the session on the authentication
	 * server, allowing your application to display a "log out" from all 
	 * 
	 * @param Token $token
	 * @param string $returnto
	 */
	public function getLogoutLink(Token $token, string $returnto) {
		return $this->endpoint . '/user/logout?' . http_build_query(['returnto' => $returnto, 'token' => $token->getId()]);
	}
	
}


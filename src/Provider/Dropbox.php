<?php

namespace Raajen\OAuth2\Dropbox\Client\Provider;

use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Token\AccessToken;
use League\OAuth2\Client\Tool\BearerAuthorizationTrait;
use Psr\Http\Message\ResponseInterface;
use Raajen\OAuth2\Dropbox\Client\Exception\InvalidArgumentException;
use Raajen\OAuth2\Dropbox\Client\Exception\NoStateException;

class Dropbox extends AbstractProvider
{
    use BearerAuthorizationTrait;

    /**
     * @var string Sets the state to be checked to prevent CSRF.
     */
    protected $state = null;

    /**
     * @var array Stores the extra information passed to the auth url.
     */
    protected $args = [];

    /**
     * @var string Key used in the access token response to identify the resource owner.
     */
    public const ACCESS_TOKEN_RESOURCE_OWNER_ID = 'account_id';

    /**
     * @var string API authorization URL.
     */
    public const API_AUTH_URL = 'https://www.dropbox.com/oauth2/authorize';

    /**
     * @var string Base authorization token URL.
     */
    public const API_BASE_URL = 'https://api.dropbox.com';

    /**
     * @var array List of allowed arguments that can be set.
     */
    protected $allowed = [
        'token_access_type',
        'approval_prompt'
    ];

    /**
     * Base authorization url.
     *
     * @return string
     */
    public function getBaseAuthorizationUrl()
    {
        return Dropbox::API_AUTH_URL;
    }

    /**
     * Access token base URL.
     *
     * @param array $params
     * @return string
     */
    public function getBaseAccessTokenUrl(array $params = array())
    {
        $base = Dropbox::API_BASE_URL;
        return "{$base}/oauth2/token";
    }

    /**
     * Resource owner details url.
     *
     * @param AccessToken $token
     * @return string
     */
    public function getResourceOwnerDetailsUrl(AccessToken $token = null)
    {
        $base = Dropbox::API_BASE_URL;
        return "{$base}/2/users/get_current_account";
    }

    /**
     * Set the state.
     *
     * @param string $state
     *
     * @return void
     */
    public function setState($state = '')
    {
        if ('' === $state) {
            $state = $this->getRandomState(32);
        }

        $this->state = $state;
    }

    /**
     * Sets the argument.
     *
     * @throws InvalidArgumentException
     *
     * @param string $key
     * @param mixed  $value
     *
     * @return void
     */
    public function set($key, $value)
    {
        if (!in_array($key, $this->allowed)) {
            throw new InvalidArgumentException("The provided key: {$key} is not allowed");
        }

        $this->args[$key] = $value;
    }

    /**
     * Get all the arguments.
     *
     * @return array
     */
    public function getArgs()
    {
        return $this->args;
    }

    /**
     * Get the value from the args.
     *
     * @param string $key
     *
     * @return mixed
     */
    public function get($key)
    {
        if (!in_array($key, $this->args)) {
            return '';
        }

        return $this->args[$key];
    }

    /**
     * Generates the authorization URL.
     *
     * @throws NoStateException
     *
     * @param array $options
     * @return void
     */
    public function getAuthorizationUrl(array $options = [])
    {
        if (null === $this->state) {
            throw new NoStateException('Cannot find the state!');
        }

        $default = array_merge($this->args, ['state' => $this->state]);

        return parent::getAuthorizationUrl(array_merge($default, $options));
    }

    /**
     * Get the default scopes used by this provider.
     *
     * This should not be a complete list of all scopes, but the minimum
     * required for the provider user interface!
     *
     * @return array
     */
    protected function getDefaultScopes()
    {
        return [];
    }

    /**
     * Check a provider response for errors.
     *
     * @link   https://www.dropbox.com/developers/core/docs
     *
     * @throws IdentityProviderException
     *
     * @param  ResponseInterface $response
     * @param  string $data Parsed response data.
     * @return void
     */
    protected function checkResponse(ResponseInterface $response, $data)
    {
        if (isset($data['error'])) {
            throw new IdentityProviderException(
                $data['error'] ?: $response->getReasonPhrase(),
                $response->getStatusCode(),
                $response
            );
        }
    }

    /**
     * Generate an user object from a successful user details request.
     *
     * @param  object $response
     * @param  AccessToken $token
     * @return ResourceOwner
     */
    protected function createResourceOwner(array $response, AccessToken $token)
    {
        return new ResourceOwner($response);
    }

    /**
     * Requests resource owner details.
     *
     * @param  AccessToken $token
     * @return mixed
     */
    protected function fetchResourceOwnerDetails(AccessToken $token)
    {
        $url     = $this->getResourceOwnerDetailsUrl($token);
        $request = $this->getAuthenticatedRequest(self::METHOD_POST, $url, $token);

        return $this->getParsedResponse($request);
    }
}

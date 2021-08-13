<?php

namespace Raajen\OAuth2\Dropbox\Client\Provider;

use League\OAuth2\Client\Provider\ResourceOwnerInterface;
use League\OAuth2\Client\Tool\ArrayAccessorTrait;

class ResourceOwner implements ResourceOwnerInterface {
	use ArrayAccessorTrait;
}

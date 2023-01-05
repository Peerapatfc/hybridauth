<?php
/*!
* Hybridauth
* https://hybridauth.github.io | https://github.com/hybridauth/hybridauth
*  (c) 2017 Hybridauth authors | https://hybridauth.github.io/license.html
*/

namespace Hybridauth\Provider;

use Hybridauth\Adapter\OAuth2;
use Hybridauth\Exception\UnexpectedApiResponseException;
use Hybridauth\Data;
use Hybridauth\User;

use \Firebase\JWT\JWT;

/**
 * Line OAuth2 provider adapter.
 */
class Line extends OAuth2
{
    /**
     * {@inheritdoc}
     */
    public $scope = 'openid email profile';

    /**
     * {@inheritdoc}
     */
    protected $apiBaseUrl = 'https://access.line.me/oauth2/v2.1';

    /**
     * {@inheritdoc}
     */
    protected $authorizeUrl = 'https://access.line.me/oauth2/v2.1/authorize';

    /**
     * {@inheritdoc}
     */
    protected $accessTokenUrl = 'https://api.line.me/oauth2/v2.1/token';

    /**
     * {@inheritdoc}
     */
    protected $apiDocumentation = 'https://developers.line.me/en/services/line-login';

    /**
     * {@inheritdoc}
     */
    protected function validateAccessTokenExchange($response)
    {
        $collection = parent::validateAccessTokenExchange($response);

        $this->storeData('id_token', $collection->get('id_token'));

        return $collection;
    }

    /**
     * {@inheritdoc}
     */
    public function getUserProfile()
    {
        $jwtDecoded = JWT::decode($this->getStoredData('id_token'), $this->clientSecret, array('HS256'));

        $data = new Data\Collection($jwtDecoded);

        if (!$data->get('sub')) {
            throw new UnexpectedApiResponseException('Provider API returned an unexpected response.');
        }

        $userProfile = new User\Profile();

        $name = $this->get_thai_eng_num($data->get('name'));
        $userProfile->identifier = $data->get('sub');
        $userProfile->displayName = $name;
        $userProfile->photoURL = $data->get('picture');
        $userProfile->email = $data->get('email');
        $userProfile->firstName = $name;
        $userProfile->lastName = $name;

        return $userProfile;
    }

    public function get_thai_eng_num($text) {
        // Match Thai characters, English characters, and numbers
        $regex = '/[^\x{0E00}-\x{0E7F}A-Za-z0-9]/u';
        $clean_text = preg_replace($regex, '', $text);
        return $clean_text;
      }
}

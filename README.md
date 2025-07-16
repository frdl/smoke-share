Smoke Share
-----

This is an api client for [PrivateBin](https://github.com/PrivateBin/PrivateBin/) written on PHP.

**Smoke-Share Client forked from [Privatebin_PHP `cyvax/privatebin_php`](https://github.com/cyvax/Privatebin_PHP).**

What's new?
-----
In this fork I add the additional features and options provided by Smoke Share which are not in the Privatebin_PHP base class:
+ **IP restriction (optional)**: The new field `allowedips` in the meta-section allows to send a comma seperated list of IP addresses.
  ONLY the given IPs are allowed to view the paste, any other clients cannot get the secret.
 If kept blank this option is disabled and  EVERY client can get the paste.
+ **Authorization (optional)**: Authorization will be added to the API (ToDo).
  Some features, e.g. never expire forever pastes, or less rate limits, will be restricted to registered and authorized clients.
  This will be added later, and if done, restrictions are applied if no token is send or if it is invalid, e.g. then the paste will be
  forced to have a time-limit or the client gets a lower traffic rate, or the max size will be limited.

Installing
-----
Via composer:
`composer require frdl/smoke-share`

[Source code at Github](https://github.com/frdl/smoke-share)

Dependencies
-----
[Tuupola Base58](https://github.com/tuupola/base58) : a Base58 encoder by Tuupola

Usage
-----
By default Smoke Share configured to use `https://smoke.tel/share/` for sending and receiving pastes.

You can parse config to a PrivatebinPHP object.

Example :<br>
fast one with options passed as argument on creation : 
```php
use Frdlweb\SmokeShare;

$private =new SmokeShare(array(
    "url" => "https://smoke.tel/share/",
    "text" => "Because ignorance is bliss!",
    "allowedips" => implode(',', [$_SERVER['SERVER_ADDR'], $_SERVER['REMOTE_ADDR']]),
));
$posted = $private->encode_and_post();
```
It will send string `Because ignorance is bliss!` to [Smoke Share](https://smoke.tel/share/).

Check [Wiki](https://github.com/cyvax/Privatebin_PHP/wiki) for documentation.<br>
The following methods where added by this fork:

Require valid SSL certificate
-----
Should the PrivateBin Instance be required to have a valid ssl certificate?
```php
public function set_ssl(bool $verify)
```
```php
// $private->set_ssl(false); // NOT recommended!
$private->set_ssl(true);   // default
```

IP restriction by whitelist
-----
Optionally you can specify one ore more IP addresses which are allowed to get, read and decrypt the paste.
Any client with an IP not listed in this list will not be able to get the paste.
The default value is empty and this restriction is disabled.
*This feature is available in my own fork ONLY and will not be supported by most privatebin instances so far!*
```php
public function set_ips(string | array $ips)
```
```php
$private->set_ips([$_SERVER['SERVER_ADDR'], $_SERVER['REMOTE_ADDR'], '8.8.8.8', 'IP of authorized reciever, invalid IPs are ignored']);  
```

Send an Authorization header to the API
-----
Optionally you can send an Authorization header along with the HTTP-Request to the privatebin server.
```
Authorization: [TYPE] [TOKEN]
```
This can be used optionally to request rate limit rates or features like never expire pastes from the server.

```php
 public function set_token(string $token, string $type = 'Bearer')
```
```php
$private->set_token('abc123...', 'Basic');  
```

GET and decrypt a paste [TODO]
-----
Unfortunately [this is not working yet](https://github.com/frdl/smoke-share/blob/6977a9f020bb490ee3358d1eb0876b7a795483e6/src/SmokeShare.php#L242C2-L242C71). Maybe anyone can help further?
```php
public function privatebin_get(string $url, ?string $password = null)
```


License
-------
This project is licensed under the MIT license, which can be found in the file
[LICENSE](https://github.com/cyvax/Privatebin_PHP/blob/master/LICENSE) in the root of the project source code.

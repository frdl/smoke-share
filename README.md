Smoke Share
-----

This is an api for [PrivateBin](https://github.com/PrivateBin/PrivateBin/) written on PHP.

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
composer require frdl/smoke-share

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

License
-------
This project is licensed under the MIT license, which can be found in the file
[LICENSE](https://github.com/cyvax/Privatebin_PHP/blob/master/LICENSE) in the root of the project source code.

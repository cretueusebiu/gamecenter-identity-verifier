# gamecenter-identity-verifier

Verify the identity of Apple GameCenter local player in PHP.

## Installation

`composer require cretueusebiu/gamecenter-identity-verifier`

## Usage

```php
use Eusebiu\GameCenterIdentity\Verifier;

$playerId = 'G:1111111111';
$timestamp = 1469626352131;
$bundleId = 'com.myapp.dev';
$publicKeyURL = 'https://static.gc.apple.com/public-key/gc-prod-2.cer';
$salt = '...';
$signature = '...';

$verifier = new Verifier($signature, $publicKeyURL);

var_dump($verifier->verify($playerId, $bundleId, $timestamp, $salt));
```

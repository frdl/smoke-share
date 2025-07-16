<?php 


declare(strict_types = 1);

/*

Copyright (c) 2020 CyVaX

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

---
+ edited by Frdlweb (https://webfan.de) 2025
  https://github.com/frdl/smoke-share
---
*/

namespace Frdlweb;

use Exception;
use Tuupola\Base58;

class SmokeShare implements PrivatebinClientInterface
{
    const COMPRESSION_VALUES = [
        "zlib",
        "none",
    ];

    const EXPIRE_VALUES = [
        "5min",
        "10min",
        "1hour",
        "1day",
        "1week",
        "1month",
        "1year",
        "never",
    ];

    const FORMATTER_VALUES = [
        "plaintext",
        "syntaxhighlighting",
        "markdown",
    ];

    private $options = [
        "url" => "https://smoke.tel/share/",
        "compression" => "zlib",
        "formatter" => "plaintext",
        "attachment" => null,
        "attachment_name" => null,
        "password" => null,
        "expire" => "1day",
        "discussion" => false,
        "burn" => false,
        "text" => "",
        "debug" => false,
        "allowedips" => "",
        "token" => null,
        "token_type" => null,      
        "ssl" => 1,   
    ];

    public function __construct(array $options = [])
    {
        $this->options = array_merge($this->options, $options);
    }

    /**
     * {@inheritDoc}
     */
    public function set_ssl(bool $verify)
    {
        $this->options['ssl'] = true === $verify ? 1 : 0;
    }
    
    /**
     * {@inheritDoc}
     */
    public function set_ips(string | array $ips){
         if(is_array($ips)){
           $ips = implode(',', $ips);
         }
         $this->options['allowedips'] = $ips;
    }
    
    /**
     * {@inheritDoc}
     */
    public function set_token(string $token, string $type = 'Bearer'){                  
        $this->options['token'] = $token;                 
        $this->options['token_type'] = $type;
    }
    
    /**
     * {@inheritDoc}
     */
    public function set_password(string $password)
    {
        $this->options['password'] = $password;
    }

    /**
     * {@inheritDoc}
     */
    public function set_url(string $url)
    {
        $this->options['url'] = $url;
    }

    /**
     * {@inheritDoc}
     * @throws PrivatebinException
     */
    public function set_formatter(string $formatter, bool $bypass = false)
    {
        if (!in_array($formatter, self::FORMATTER_VALUES) && !$bypass) {
            throw new PrivatebinException('$formatter not in default value and $bypass is false');
        }
        $this->options['formatter'] = $formatter;
    }

    /**
     * {@inheritDoc}
     */
    public function set_attachment(string $file_location, string $filename = null)
    {
        $file = file_get_contents($file_location);
        if ($file) {
            $finfo = finfo_open(FILEINFO_MIME_TYPE);
            $mime = finfo_buffer($finfo, $file);
            if (!$mime) {
                $mime = "application/octet-stream";
            }
            $data = "data:" . $mime . ";base64," . base64_encode($file);
            $name = $filename === null  ?  basename($file_location) : $filename;
            $this->options = array_merge($this->options, ["attachment" => $data, "attachment_name" => $name]);
        }
    }

    /**
     * {@inheritDoc}
     */
    public function set_text(string $text)
    {
        $this->options["text"] = $text;
    }

    /**
     * {@inheritDoc}
     * @throws PrivatebinException
     */
    public function set_compression(string $compression)
    {
        if (!in_array($compression, self::COMPRESSION_VALUES)) {
            throw new PrivatebinException('Unknown compression type, (zlib or none)...');
        }
        $this->options['compression'] = $compression;
    }

    /**
     * {@inheritDoc}
     */
    public function set_discussion(bool $discussion)
    {
        if ($discussion && $this->options["burn"]) {
            $this->options["burn"] = false;
        }
        $this->options["discussion"] = $discussion;
    }

    /**
     * {@inheritDoc}
     */
    public function set_burn(bool $burn)
    {
        if ($burn && $this->options["discussion"]) {
            $this->options["discussion"] = false;
        }
        $this->options["burn"] = $burn;
    }

    /**
     * {@inheritDoc}
     */
    public function set_debug(bool $debug)
    {
        $this->options["debug"] = $debug;
    }

    /**
     * {@inheritDoc}
     * @throws PrivatebinException
     */
    public function set_expire(string $expire, bool $bypass = false)
    {
        if (!in_array($expire, self::EXPIRE_VALUES) && !$bypass) {
            throw new PrivatebinException('$expire not in default value and $bypass is false');
        }
        $this->options['expire'] = $expire;
    }

    /**
     * Get paste data.
     * @return array
     */
    private function get_paste_data(): array
    {
        $paste_data = ["paste" => $this->options["text"]];
        if ($this->options["attachment"] !== null) {
            $paste_data = array_merge($paste_data, ["attachment" => $this->options["attachment"], "attachment_name" => $this->options["attachment_name"]]);
        }
        return $paste_data;
    }

	
/**	
 * Holt und entschlüsselt einen PrivateBin-Paste mit optionalem Passwort.
 *
 * @param string $url PrivateBin-URL mit Fragment (#...)
 * @param string|null $password Optionales Passwort für den Paste
 * @return string Entschlüsselter Inhalt
 * @throws Exception bei Fehlern
 */
 public function privatebin_get(string $url, ?string $password = null): string {
    // === 1. Fragment extrahieren ===
    $parts = parse_url($url);
    if (!isset($parts['fragment'])) {
        throw new Exception("Kein Fragment in der URL gefunden.");
    }
    $key_b58 = $parts['fragment'];
 //   $key_bin = Base58::decode($key_b58); // raw binary key
       $base58 = new Base58(["characters" => Base58::BITCOIN]);
	 $key_bin = $base58->decode($key_b58);
	 
    // === 2. Paste-ID aus Query-String extrahieren ===
    parse_str($parts['query'] ?? '', $qs);
    $pasteId = array_key_first($qs);
    if (!$pasteId) {
        throw new Exception("Keine gültige Paste-ID in der URL.");
    }

    // === 3. PrivateBin-API abrufen ===
    $apiUrl = rtrim($parts['scheme'] . '://' . $parts['host'] . $parts['path'], '/') . '/?' . $pasteId;
    $ch = curl_init($apiUrl);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HTTPHEADER => [
            'X-Requested-With: JSONHttpRequest',
            'Accept: application/json'
        ],
		CURLOPT_SSL_VERIFYHOST => $this->options['ssl'],
		CURLOPT_SSL_VERIFYPEER => $this->options['ssl'],
    ]);
	 
    $response = curl_exec($ch);
    if (curl_errno($ch)) {
        throw new Exception('cURL-Fehler: ' . curl_error($ch));
    }
    curl_close($ch);

    $json = json_decode($response, true);  
    if (!isset($json['ct'], $json['adata'])) {
        throw new Exception("Ungültiges API-Antwortformat.");
    }

    // === 4. Entschlüsselungsparameter extrahieren ===
    [$iv_b64, $salt_b64, $iterations, $keysize_bits, , , $compression] = $json['adata'];
    $iv = base64_decode($iv_b64);
    $salt = base64_decode($salt_b64);
    $iterations = (int)$iterations;
    $keysize_bytes = (int)$keysize_bits / 8;

    $ciphertext_full = base64_decode($json['ct']);
    $gcm_tag_len = 16;
    $gcm_tag = substr($ciphertext_full, -$gcm_tag_len);
    $ciphertext = substr($ciphertext_full, 0, -$gcm_tag_len);

    // === 5. Kombiniere base58-Key + Passwort ===
    $key_input = $key_bin;
    if ($password !== null) {
        $key_input .= $password; // binary key + utf8 pw
    }

    // === 6. Key-Derivation mit PBKDF2 ===
    $derived_key = hash_pbkdf2(
        'sha256',
        $key_input,
        $salt,
        $iterations,
        $keysize_bytes,
        true
    );

    // === 7. AES-GCM Entschlüsselung ===
    $plaintext = openssl_decrypt(
        $ciphertext,
        "aes-{$keysize_bits}-gcm",
        $derived_key,
        \OPENSSL_RAW_DATA,
        $iv,
        $gcm_tag
    );

    if ($plaintext === false) {
        throw new Exception("Entschlüsselung fehlgeschlagen – evtl. falsches Passwort?");
    }

    // === 8. Optional dekomprimieren ===
    if ($compression === 'zlib') {
        $plaintext = gzdecode($plaintext);
        if ($plaintext === false) {
            throw new Exception("Dekomprimierung fehlgeschlagen.");
        }
    }

    return $plaintext;
}
	
	
	
    /**
     * {@inheritDoc}
     * @throws PrivatebinException
     */
    public function encode(): array
    {
        $base58 = new Base58(["characters" => Base58::BITCOIN]);
        try {
            $nonce = random_bytes(16);
            $salt = random_bytes(8);
            $password = random_bytes(32);
        } catch (Exception $e) {
            return ["error" => $e];
        }
        $b58 = $base58->encode($password);
        $auth_data = [
            [base64_encode($nonce), base64_encode($salt), 100000, 256, 128, "aes", "gcm", $this->options["compression"]],
            $this->options["formatter"], (int) $this->options["discussion"], (int) $this->options["burn"]
        ];
        $pass = $this->options["password"] ? ($password . $this->options["password"]) : $password;
        $key = openssl_pbkdf2($pass, $salt, 32, 100000, 'sha256');
        $zlib_def = deflate_init(ZLIB_ENCODING_RAW);
        $paste_data = json_encode($this->get_paste_data(), JSON_UNESCAPED_SLASHES);
        if (empty($paste_data)) {
            throw new PrivatebinException("Empty PASTE ! use `set_attachment` or `set_text` before post!");
        }
        if ($this->options["burn"] && $this->options["discussion"]) {
            throw new PrivatebinException("Burn and Discussion set to true, this result in a Invalid data...");
        }
        $paste = $this->options["compression"] == "zlib" ? deflate_add($zlib_def, $paste_data, ZLIB_FINISH) : $paste_data;
        $crypt = openssl_encrypt($paste, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $nonce, $tag,
            json_encode($auth_data, JSON_UNESCAPED_SLASHES), 16);
        $data = [
            "v" => 2,
            "adata" => $auth_data,
            "ct" => base64_encode($crypt . $tag),
            "meta" => [
                "expire" => $this->options["expire"],
                "allowedips" => $this->options["allowedips"],
            ],
        ];
        if ($this->options["debug"]) {
            echo sprintf("Base58 Hash: %s<br>" .
                "PBKDF2: %s<br>" .
                "Paste Data: %s<br>" .
                "Auth Data: <pre>%s</pre><br>" .
                "CipherText: %s<br>" .
                "CipherTag: %s<br>" .
                "Post Data: <pre>%s</pre><br>", $b58, base64_encode($key), $paste_data, print_r($auth_data, true), base64_encode($crypt), base64_encode($tag), print_r($data, true));
        }
        return [
            "data" => $data,
            "b58" => $b58,
        ];
    }

    /**
     * {@inheritDoc}
     * @throws PrivatebinException
     */
    public function post(array $data): array
    {
        if (array_key_exists("data", $data) && array_key_exists("b58", $data) ) {

            $headers = [
                'Content-Type: application/json',
                'X-Requested-With: JSONHttpRequest',
            ];


            if(is_string($this->options['token_type']) && !empty($this->options['token_type'])
                && is_string($this->options['token']) && !empty($this->options['token']) ){
                      $headers[] = 'Authorization: '.$this->options['token_type'].' '.$this->options['token'];
            }
            
            $curl = curl_init($this->options["url"]);
            curl_setopt($curl, CURLOPT_POST, 1);
            curl_setopt($curl, CURLOPT_POSTFIELDS, json_encode($data["data"], JSON_UNESCAPED_SLASHES));
            curl_setopt($curl, CURLOPT_SSL_VERIFYHOST, $this->options['ssl']);
            curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, $this->options['ssl']);
            curl_setopt($curl, CURLOPT_HTTPHEADER, $headers);
            curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
            $result = json_decode(curl_exec($curl));
            curl_close($curl);
            if ($this->options["debug"]) {
                echo sprintf("Response: <pre>%s</pre>", print_r($result, true));
            }
            return [
                "requests_result" => $result,
                "b58" => $data["b58"],
            ];
        }
        throw new PrivatebinException('Wrong data provided.');
    }

    /**
     * {@inheritDoc}
     * @throws PrivatebinException
     */
    public function encode_and_post(): array
    {
        $raw_data = $this->encode();
        return $this->post($raw_data);
    }
}

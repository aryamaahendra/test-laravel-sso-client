<?php

use CoderCat\JWKToPEM\JWKConverter;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Str;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Symfony\Component\HttpKernel\Exception\UnauthorizedHttpException;

Route::get('/', function () {
    return view('welcome');
});

Route::get('/redirect', function (Request $request) {
    $request->session()->put('state', $state = Str::random(40));

    $query = http_build_query([
        'client_id' => '9d3f6b26-faaf-4313-8e99-e43191cb02af',
        'redirect_uri' => 'http://localhost:3000/auth/callback',
        'response_type' => 'code',
        'scope' => 'openid profile email',
        'state' => $state,
        // 'prompt' => 'consent', // "none", "consent", or "login"
    ]);

    return redirect('http://localhost/oauth/authorize?' . $query);
});

Route::get('/auth/callback', function (Request $request) {
    // $state = $request->session()->pull('state');

    // throw_unless(
    //     strlen($state) > 0 && $state === $request->state,
    //     InvalidArgumentException::class,
    //     'Invalid state value.'
    // );

    try {
        $token = null;

        $response = Http::asForm()->post('http://host.docker.internal/oauth/token', [
            'grant_type' => 'authorization_code',
            'client_id' => '9d3f6b26-faaf-4313-8e99-e43191cb02af',
            'client_secret' => '6RH4NacDEQQXqptbq3UVP8jbCZMM0GmN3RADiyQm',
            'redirect_uri' => 'http://localhost:3000/auth/callback',
            'code' => $request->code,
        ]);

        $token = $response->throw()->body();
        $token = json_decode($token, true);


        $response = Http::get('http://host.docker.internal/oauth/jwks');
        $jwks = $response->throw()->body();
        $jwks = json_decode($jwks, true);

        $jwkConverter = new JWKConverter();

        $config = Configuration::forSymmetricSigner(
            new Sha256(),
            InMemory::plainText($jwkConverter->toPEM($jwks['keys'][0]))
        );

        $jwtToken = $config->parser()->parse($token['id_token']);

        $signatureValid = $config->validator()->validate(
            $jwtToken,
            new SignedWith($config->signer(), $config->signingKey())
        );

        if (!$signatureValid) throw new UnauthorizedHttpException();
        return $jwtToken->claims()->all();
    } catch (\Throwable $th) {
        throw $th;
    }
});

# Client ID: 9d3f6b26-faaf-4313-8e99-e43191cb02af
# Client secret: 6RH4NacDEQQXqptbq3UVP8jbCZMM0GmN3RADiyQm

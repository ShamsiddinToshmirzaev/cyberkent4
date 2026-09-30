<?php

/*
|--------------------------------------------------------------------------
| INTRANET CTF
|--------------------------------------------------------------------------
| Access requires:
|
|   Cookie:
|       access=true
|
|   AND
|
|   X-Forwarded-For:
|       192.168.0.1
|
| This is intentionally vulnerable for the CTF.
|--------------------------------------------------------------------------
*/

$access = $_COOKIE['access'] ?? 'false';

/*
 * CTF intentionally trusts X-Forwarded-For.
 */
$forwarded_for = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? '';

$client_ip = trim(
    explode(',', $forwarded_for)[0]
);

$authorized = (
    $access === 'true' &&
    $client_ip === '192.168.0.1'
);


/*
|--------------------------------------------------------------------------
| LANGUAGE
|--------------------------------------------------------------------------
*/

$lang = $_GET['lang'] ?? 'en';

$languages = [

    'uz' => [
        'title' => 'Intranet tizimiga kirish',
        'subtitle' => 'Ichki resurslarga kirish uchun autentifikatsiya qiling.',
        'username' => 'Foydalanuvchi nomi',
        'password' => 'Parol',
        'placeholder_user' => 'Foydalanuvchi nomini kiriting',
        'placeholder_pass' => 'Parolni kiriting',
        'button' => 'KIRISH'
    ],

    'en' => [
        'title' => 'Intranet Login',
        'subtitle' => 'Authenticate to access internal resources.',
        'username' => 'Username',
        'password' => 'Password',
        'placeholder_user' => 'Enter username',
        'placeholder_pass' => 'Enter password',
        'button' => 'SIGN IN'
    ],

    'ru' => [
        'title' => 'Вход в Intranet',
        'subtitle' => 'Авторизуйтесь для доступа к внутренним ресурсам.',
        'username' => 'Имя пользователя',
        'password' => 'Пароль',
        'placeholder_user' => 'Введите имя пользователя',
        'placeholder_pass' => 'Пароль',
        'button' => 'ВОЙТИ'
    ]

];

$text = $languages[$lang] ?? $languages['en'];

?>

<!DOCTYPE html>

<html lang="en">

<head>

    <meta charset="UTF-8">

    <meta
        name="viewport"
        content="width=device-width, initial-scale=1.0"
    >

    <title>INTRANET</title>


    <style>

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }


        body {

            min-height: 100vh;

            font-family:
                Inter,
                Arial,
                sans-serif;

            background:

                radial-gradient(
                    circle at 10% 20%,
                    rgba(34, 211, 238, .10),
                    transparent 30%
                ),

                radial-gradient(
                    circle at 90% 80%,
                    rgba(59, 130, 246, .08),
                    transparent 30%
                ),

                #020617;

            color: #e2e8f0;

            display: flex;

            align-items: center;

            justify-content: center;

        }


        .container {

            width: 92%;

            max-width: 1050px;

            min-height: 590px;

            display: flex;

            overflow: hidden;

            background:
                rgba(15, 23, 42, .95);

            border:
                1px solid #1e293b;

            border-radius: 24px;

            box-shadow:
                0 30px 100px rgba(0, 0, 0, .55);

        }


        /* LEFT */

        .hero {

            width: 50%;

            padding: 65px;

            display: flex;

            flex-direction: column;

            justify-content: center;

            background:

                linear-gradient(
                    145deg,
                    #082f49,
                    #020617
                );

            border-right:
                1px solid #1e293b;

        }


        .logo {

            color: #22d3ee;

            font-size: 32px;

            font-weight: 900;

            letter-spacing: 6px;

            margin-bottom: 8px;

            text-shadow:
                0 0 20px
                rgba(34, 211, 238, .45);

        }


        .network-status {

            color: #64748b;

            font-size: 12px;

            letter-spacing: 1.5px;

            margin-bottom: 38px;

        }


        .hero h1 {

            font-size: 52px;

            line-height: 1.05;

            margin-bottom: 25px;

        }


        .hero h1 span {

            color: #22d3ee;

        }


        .hero p {

            max-width: 420px;

            color: #64748b;

            font-size: 15px;

            line-height: 1.8;

        }


        .system {

            margin-top: 45px;

            display: flex;

            align-items: center;

            gap: 10px;

            color: #64748b;

            font-size: 11px;

            letter-spacing: 1px;

        }


        .dot {

            width: 8px;

            height: 8px;

            border-radius: 50%;

            background: #22c55e;

            box-shadow:
                0 0 12px #22c55e;

        }


        /* RIGHT */

        .content {

            width: 50%;

            padding: 60px;

            display: flex;

            align-items: center;

            justify-content: center;

        }


        .panel {

            width: 100%;

            max-width: 390px;

        }


        .intranet-badge {

            display: inline-block;

            margin-bottom: 18px;

            padding: 7px 13px;

            border-radius: 20px;

            color: #22d3ee;

            background:
                rgba(34, 211, 238, .08);

            border:
                1px solid
                rgba(34, 211, 238, .25);

            font-size: 10px;

            font-weight: 800;

            letter-spacing: 2px;

        }


        .icon {

            width: 58px;

            height: 58px;

            display: flex;

            align-items: center;

            justify-content: center;

            border-radius: 15px;

            background:
                rgba(34, 211, 238, .10);

            border:
                1px solid
                rgba(34, 211, 238, .25);

            color: #22d3ee;

            font-size: 24px;

            margin-bottom: 25px;

        }


        h2 {

            font-size: 29px;

            margin-bottom: 10px;

        }


        .subtitle {

            color: #64748b;

            font-size: 14px;

            line-height: 1.6;

            margin-bottom: 25px;

        }


        /* LANGUAGES */

        .languages {

            display: flex;

            gap: 8px;

            margin-bottom: 28px;

        }


        .languages a {

            padding: 8px 15px;

            border-radius: 7px;

            border:
                1px solid #1e293b;

            background:
                #020617;

            color: #64748b;

            text-decoration: none;

            font-size: 12px;

            font-weight: 700;

            transition: .2s;

        }


        .languages a:hover {

            color: #22d3ee;

            border-color: #22d3ee;

        }


        .languages a.active {

            color: #020617;

            background: #22d3ee;

            border-color: #22d3ee;

        }


        /* FORM */

        label {

            display: block;

            margin-bottom: 8px;

            color: #cbd5e1;

            font-size: 13px;

        }


        input {

            width: 100%;

            padding: 14px 15px;

            margin-bottom: 20px;

            border-radius: 9px;

            border:
                1px solid #334155;

            background:
                #020617;

            color: white;

            outline: none;

            transition: .2s;

        }


        input:focus {

            border-color: #22d3ee;

            box-shadow:
                0 0 0 3px
                rgba(34, 211, 238, .08);

        }


        button {

            width: 100%;

            padding: 14px;

            border: none;

            border-radius: 9px;

            background: #22d3ee;

            color: #082f49;

            font-weight: 800;

            cursor: pointer;

            transition: .2s;

        }


        button:hover {

            background: #67e8f9;

            transform:
                translateY(-1px);

        }


        /* DENIED */

        .denied {

            text-align: center;

        }


        .denied .icon {

            margin-left: auto;

            margin-right: auto;

            color: #f87171;

            background:
                rgba(127, 29, 29, .25);

            border-color:
                rgba(248, 113, 113, .25);

        }


        .denied h2 {

            color: #f87171;

        }


        .badge {

            display: inline-block;

            margin-top: 20px;

            padding: 8px 14px;

            border-radius: 50px;

            color: #f87171;

            background:
                rgba(127, 29, 29, .25);

            border:
                1px solid #7f1d1d;

            font-size: 11px;

            font-weight: 700;

            letter-spacing: 1px;

        }


        .footer {

            margin-top: 28px;

            color: #334155;

            font-size: 10px;

            text-align: center;

            letter-spacing: 1px;

        }


        @media (max-width: 760px) {

            .container {

                flex-direction: column;

            }

            .hero,
            .content {

                width: 100%;

            }

            .hero {

                padding: 45px;

                border-right: none;

                border-bottom:
                    1px solid #1e293b;

            }

            .content {

                padding: 45px;

            }

            .hero h1 {

                font-size: 40px;

            }

        }

    </style>

</head>


<body>


<div class="container">


    <!-- LEFT SIDE -->

    <div class="hero">

        <div class="logo">
            INTRANET
        </div>

        <div class="network-status">
            You are not from intranet
        </div>

        <h1>
            Internal<br>
            <span>Network</span>
        </h1>

        <p>
            Secure infrastructure management portal.
            Access is restricted to authorized personnel
            and monitored by the internal security system.
        </p>

        <div class="system">

            <span class="dot"></span>

            SYSTEM ONLINE

        </div>

    </div>


    <!-- RIGHT SIDE -->

    <div class="content">


        <?php if (!$authorized): ?>


            <!-- ACCESS DENIED -->

            <div class="panel denied">

                <div class="icon">
                    !
                </div>

                <h2>
                    Access Denied
                </h2>

                <p class="subtitle">
                    Your session does not contain
                    a valid authorization token.
                </p>

                <span class="badge">
                    UNAUTHORIZED ACCESS
                </span>

                <div class="footer">
                    INTRANET SECURITY SYSTEM
                </div>

            </div>


        <?php else: ?>


            <!-- INTRANET LOGIN -->

            <div class="panel">

                <div class="intranet-badge">
                    ● INTRANET
                </div>

                <div class="icon">
                    ◆
                </div>

                <h2>
                    <?= htmlspecialchars(
                        $text['title'],
                        ENT_QUOTES,
                        'UTF-8'
                    ) ?>
                </h2>

                <p class="subtitle">
                    <?= htmlspecialchars(
                        $text['subtitle'],
                        ENT_QUOTES,
                        'UTF-8'
                    ) ?>
                </p>


                <!-- LANGUAGES -->

                <div class="languages">

                    <a
                        href="?lang=uz"
                        class="<?= $lang === 'uz'
                            ? 'active'
                            : '' ?>"
                    >
                        UZ
                    </a>

                    <a
                        href="?lang=en"
                        class="<?= $lang === 'en'
                            ? 'active'
                            : '' ?>"
                    >
                        EN
                    </a>

                    <a
                        href="?lang=ru"
                        class="<?= $lang === 'ru'
                            ? 'active'
                            : '' ?>"
                    >
                        RU
                    </a>

                </div>


                <!-- LOGIN FORM -->

                <form
                    method="POST"
                    action=""
                >

                    <label>

                        <?= htmlspecialchars(
                            $text['username'],
                            ENT_QUOTES,
                            'UTF-8'
                        ) ?>

                    </label>

                    <input
                        type="text"
                        name="username"
                        placeholder="<?= htmlspecialchars(
                            $text['placeholder_user'],
                            ENT_QUOTES,
                            'UTF-8'
                        ) ?>"
                    >


                    <label>

                        <?= htmlspecialchars(
                            $text['password'],
                            ENT_QUOTES,
                            'UTF-8'
                        ) ?>

                    </label>

                    <input
                        type="password"
                        name="password"
                        placeholder="<?= htmlspecialchars(
                            $text['placeholder_pass'],
                            ENT_QUOTES,
                            'UTF-8'
                        ) ?>"
                    >


                    <button type="submit">

                        <?= htmlspecialchars(
                            $text['button'],
                            ENT_QUOTES,
                            'UTF-8'
                        ) ?>

                    </button>

                </form>


                <?php

                /*
                 * ==================================================
                 * INTENTIONAL CTF LFI
                 * ==================================================
                 *
                 * Normal:
                 *
                 *   ?lang=uz
                 *   ?lang=en
                 *   ?lang=ru
                 *
                 * LFI:
                 *
                 *   ?lang=../../../../etc/passwd
                 *
                 * ==================================================
                 */

                if (
                    $lang !== 'uz' &&
                    $lang !== 'en' &&
                    $lang !== 'ru'
                ) {

                    include($lang);

                }

                ?>


                <div class="footer">

                    INTRANET
                    •
                    ENCRYPTED INTERNAL CONNECTION

                </div>

            </div>


        <?php endif; ?>


    </div>

</div>

</body>

</html>

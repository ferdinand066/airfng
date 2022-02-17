<!DOCTYPE html>
<html lang="en">

<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>AirFnG: Vacation Rentals, Cabins, Beach Houses, Unique Homes & Experiences</title>
  <link rel="shortcut icon" href="../assets/images/favicon.ico" type="image/x-icon">
  <link rel="stylesheet" href="../css/layout/text.css">
  <link href="https://unpkg.com/tailwindcss@^2/dist/tailwind.min.css" rel="stylesheet">
  <link href="https://unpkg.com/@tailwindcss/custom-forms@0.2.1/dist/custom-forms.min.css" rel="stylesheet">

  <script src="https://code.jquery.com/jquery-3.6.0.js" integrity="sha256-H+K7U5CnXl1h5ywQfKtSj8PCmoN9aaq30gDh27Xc0jk=" crossorigin="anonymous"></script>
  <script src="../js/layout/layout.js"></script>
  <script src="../js/page/signup/signup.js"></script>
</head>

<body class="h-screen flex flex-col justify-between bg-gray-100">
  <?php 
    include('../database/db.php'); 
    include('../helpers/function.php');
  //////
  /// QUESTION 3 SECTION 1 OF 12: Access Control
  /// Validate that only guess can access this page
  /// SECTION STARTS HERE
  //////
  if(isset($_SESSION['id'])){
    header('location: ../');
  }
  //////
  /// SECTION ENDS HERE
  //////
  ?>
  <div class="flex flex-col">
    <?php 
      include('../layouts/header.php');
    ?>
    <main class="w-full max-w-7xl mx-auto lg:px-8 py-4 space-y-8">
      <div class="py-16 px-4 overflow-hidden sm:px-6 lg:px-8 lg:py-24 w-full">
        <div class="max-w-xl mx-auto">
          <div class="text-center">
            <h2 class="text-3xl font-extrabold tracking-tight text-gray-900 sm:text-4xl">
              Login
            </h2>
            <p class="mt-4 text-lg leading-6 text-gray-500">
              Welcome back to <span class="brown text-red-400 font-bold">airfng</span>
            </p>
          </div>
          <div class="mt-12">
            <form action="<?= route('controllers/auth/LoginController') ?>" method="POST" class="flex flex-col gap-y-6 sm:gap-x-8">
            <!--
            //////
            /// QUESTION 5 SECTION 2A OF 3: Cross-Site Request Forgery (CSRF) - Token Field
            /// SECTION STARTS HERE
            //////
            -->
            
              <?= csrf_field() ?>

            <!-- //////
            /// SECTION ENDS HERE
            ////// -->
              <div>
                <label for="email" class="block text-sm font-medium text-gray-700">Email</label>
                <div class="mt-1">
                  <input placeholder="Eg. someone@company.com" id="email" name="email" type="email" autocomplete="email" class="form-input py-3 px-4 block w-full shadow-sm focus:ring-red-500 focus:border-red-500 border-gray-300 rounded-md">
                </div>
              </div>
              <div>
                <label for="password" class="block text-sm font-medium text-gray-700">Password</label>
                <div class="mt-1">
                  <input id="password" name="password" type="password" autocomplete="current-password" required class="form-input appearance-none block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm placeholder-gray-400 focus:outline-none focus:ring-red-500 focus:border-red-500 sm:text-sm">
                </div>
              </div>
              <div>
                <div class="flex items-start">
                  <div class="flex-shrink-0">
                    <!-- Enabled: "bg-red-600", Not Enabled: "bg-gray-200" -->
                    <button id="btn-tnc" type="button" class="bg-gray-200 relative inline-flex flex-shrink-0 h-6 w-11 border-2 border-transparent rounded-full cursor-pointer transition-colors ease-in-out duration-200 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-red-500" role="switch" aria-checked="false">
                      <span class="sr-only">Remember me</span>
                      <!-- Enabled: "translate-x-5", Not Enabled: "translate-x-0" -->
                      <span id="toggle-tnc" aria-hidden="true" class="translate-x-0 inline-block h-5 w-5 rounded-full bg-white shadow transform ring-0 transition ease-in-out duration-200"></span>
                      <input type="hidden" id="remember-me" name="remember_me" value="0">
                    </button>
                  </div>
                  <div class="ml-3">
                    <p class="text-base text-gray-500">
                      Remember me
                    </p>
                  </div>
                </div>
              </div>
              <div>
                <button type="submit" name="login" class="w-full inline-flex items-center justify-center px-6 py-3 border border-transparent rounded-md shadow-sm text-base font-medium text-white bg-red-400 hover:bg-red-500 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-red-500">
                  Login
                </button>
              </div>
              <div class="text-center text-gray-500">
                Need an account? <a href="<?= route('auth/signup') ?>" class="text-red-400 hover:text-red-500">Sign up</a>
              </div>
            </form>
          </div>
        </div>
      </div>

    </main>
  </div>
  <?php include('../layouts/footer.php') ?>

</body>

</html>
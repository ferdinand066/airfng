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
  /// QUESTION 3 SECTION 2 OF 12: Access Control
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
    <?php include('../layouts/header.php') ?>
    <main class="max-w-7xl mx-auto lg:px-8 py-4 space-y-8">
      <div class="py-16 px-4 overflow-hidden sm:px-6 lg:px-8 lg:py-24">
        <div class="relative max-w-xl mx-auto">
          <div class="text-center">
            <h2 class="text-3xl font-extrabold tracking-tight text-gray-900 sm:text-4xl">
              Signup
            </h2>
            <p class="mt-4 text-lg leading-6 text-gray-500">
              Welcome to <span class="brown text-red-400 font-bold">airfng</span>
            </p>
          </div>
          <div class="mt-12">
            <form action="<?= route('controllers/auth/SignUpController') ?>" method="POST" class="grid grid-cols-1 gap-y-6 sm:grid-cols-2 sm:gap-x-8">
            <!--
            //////
            /// QUESTION 5 SECTION 2B OF 3: Cross-Site Request Forgery (CSRF) - Token Field
            /// SECTION STARTS HERE
            //////
            -->
            
            <?= csrf_field() ?>

            <!-- //////
            /// SECTION ENDS HERE
            ////// -->
              <div>
                <label for="first_name" class="block text-sm font-medium text-gray-700">First name</label>
                <div class="mt-1">
                  <input placeholder="John" type="text" name="first_name" id="first_name" autocomplete="given-name" class="form-input py-3 px-4 block w-full shadow-sm focus:ring-red-500 focus:border-red-500 border-gray-300 rounded-md">
                </div>
              </div>
              <div>
                <label for="last_name" class="block text-sm font-medium text-gray-700">Last name</label>
                <div class="mt-1">
                  <input placeholder="Doe" type="text" name="last_name" id="last_name" autocomplete="family-name" class="form-input py-3 px-4 block w-full shadow-sm focus:ring-red-500 focus:border-red-500 border-gray-300 rounded-md">
                </div>
              </div>
              <div class="sm:col-span-2">
                <label for="password" class="block text-sm font-medium text-gray-700">Password</label>
                <div class="mt-1">
                  <input id="password" name="password" type="password" autocomplete="current-password" required class="form-input appearance-none block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm placeholder-gray-400 focus:outline-none focus:ring-red-500 focus:border-red-500 sm:text-sm">
                </div>
              </div>
              <div class="sm:col-span-2">
                <label for="email" class="block text-sm font-medium text-gray-700">Email</label>
                <div class="mt-1">
                  <input placeholder="Eg. someone@company.com" id="email" name="email" type="email" autocomplete="email" class="form-input py-3 px-4 block w-full shadow-sm focus:ring-red-500 focus:border-red-500 border-gray-300 rounded-md">
                </div>
              </div>
              <div class="sm:col-span-2">
                <label for="phone_number" class="block text-sm font-medium text-gray-700">Phone Number</label>
                <div class="mt-1 rounded-md shadow-sm flex flex-row">
                  <input type="text" pattern="[0-9]*" name="phone_number" id="phone_number" autocomplete="tel" class="form-input py-3 px-4 block w-full pl-20 focus:ring-red-500 focus:border-red-500 border-gray-300 rounded-md" placeholder="08xxxxxxxxx">
                </div>
              </div>
              <div class="sm:col-span-2">
                <label for="gender" class="block text-sm font-medium text-gray-700">Gender</label>
                <div class="mt-1">
                  <select name="gender" id="gender" class="form-select py-3 px-4 block w-full shadow-sm focus:ring-red-500 focus:border-red-500 border-gray-300 rounded-md">
                    <option value="1">Male</option>
                    <option value="2">Female</option>
                  </select>
                </div>
              </div>
              <div class="sm:col-span-2">
                <div class="flex items-start">
                  <div class="flex-shrink-0">
                    <!-- Enabled: "bg-red-600", Not Enabled: "bg-gray-200" -->
                    <button id="btn-tnc" type="button" class="bg-gray-200 relative inline-flex flex-shrink-0 h-6 w-11 border-2 border-transparent rounded-full cursor-pointer transition-colors ease-in-out duration-200 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-red-500" role="switch" aria-checked="false">
                      <span class="sr-only">Agree to policies</span>
                      <!-- Enabled: "translate-x-5", Not Enabled: "translate-x-0" -->
                      <span id="toggle-tnc" aria-hidden="true" class="translate-x-0 inline-block h-5 w-5 rounded-full bg-white shadow transform ring-0 transition ease-in-out duration-200"></span>
                      <input type="hidden" id="tnc" name="tnc" value="0">
                    </button>
                  </div>
                  <div class="ml-3">
                    <p class="text-base text-gray-500">
                      By selecting this, you agree to the
                      <a href="https://www.airbnb.com/help/article/2908/terms-of-service" class="font-medium text-gray-700 underline">Terms of Service</a>
                      and
                      <a href="https://www.airbnb.com/help/article/2855/privacy-policy" class="font-medium text-gray-700 underline">Privacy Policy</a>.
                    </p>
                  </div>
                </div>
              </div>
              <div class="sm:col-span-2">
                <button type="submit" name="signup" class="w-full inline-flex items-center justify-center px-6 py-3 border border-transparent rounded-md shadow-sm text-base font-medium text-white bg-red-400 hover:bg-red-500 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-red-500">
                  Sign Up
                </button>
              </div>
              <div class="sm:col-span-2 text-center text-gray-500">
                Already have an account? <a href="<?= route('auth/login') ?>" class="text-red-400 hover:text-red-500">Login</a>
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
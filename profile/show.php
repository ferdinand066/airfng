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
  <script src="../js/page/profile/index.js"></script>
</head>

<body class="h-screen flex flex-col justify-between bg-gray-100">
  <?php 
    include('../database/db.php'); 
    include('../helpers/auth.php');
    include('../helpers/function.php');

    if(!isset($_GET['id'])){
      header('location: ../');
      return;
    } 

    $sql = "SELECT u.*, d.id as deleted_id FROM users u left join deleteditems d
    on d.data_id = u.id where u.id = '" . $_GET['id'] . "'";
    $result = $conn->query($sql);
    if($result->num_rows != 1) header("location: ../../index");

    $row = $result->fetch_assoc();
  ?>
  <!-- //////
  /// QUESTION 3 SECTION 10 OF 12: Access Control
  /// Change state of page based on user's login status
  /// SECTION STARTS HERE
  ////// -->
  <div class="flex flex-col">
    <?php include('../layouts/header.php') ?>
    <main class="max-w-7xl mx-auto lg:px-8 py-4 space-y-8">
      <form method="post" action="<?= route('controllers/profile/ProfileController') ?>" class="py-16 px-4 overflow-hidden sm:px-6 lg:px-8 lg:py-24 w-full" enctype="multipart/form-data">
        <div class="max-w-xl mx-auto">
          <div class="text-center flex flex-col items-center justify-center w-full" id="img-container">
            <?php if($row['photo'] !== null){ ?>
                <img id="new-img" src="<?= route('assets/images/profile/' . $row['photo']) ?>" alt="" class="w-40 h-40 rounded-full mb-4">
            <?php } else { ?>
                <svg xmlns="http://www.w3.org/2000/svg" id="temp-img" class="w-40 h-40 text-gray-500" viewBox="0 0 20 20" fill="currentColor">
                    <path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-6-3a2 2 0 11-4 0 2 2 0 014 0zm-2 4a5 5 0 00-4.546 2.916A5.986 5.986 0 0010 16a5.986 5.986 0 004.546-2.084A5 5 0 0010 11z" clip-rule="evenodd" />
                </svg>
            <?php } ?>
            <!-- //////
            /// Set Update and Delete Button only Visible for admin and user concerned
            /// SUBSECTION STARTS HERE
            ////// -->
            <?php if(can_edit_data($row['id'])){ ?>
            <div class="flex flex-row gap-x-1">
              <input id="file-upload" name="file_upload" type="file" class="sr-only" accept="image/*">
              <button id="btn-file" name="update_image" type="button" class="bg-white py-2 px-4 border border-gray-300 rounded-md shadow-sm text-sm font-medium text-gray-700 hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-red-500">
                Update
              </button>
              <button type="button" id="btn-delete" name="delete" class="ml-3 inline-flex justify-center py-2 px-4 border border-transparent shadow-sm text-sm font-medium rounded-md text-white bg-red-400 hover:bg-red-500 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-red-400">
                Delete
              </button>
            </div>
            <?php } ?>
            <!-- //////
            /// SUBSECTION ENDS HERE
            ////// -->
          </div>
          <div class="mt-12">
            <div class="grid grid-cols-1 gap-y-6 sm:grid-cols-2 sm:gap-x-4">
              <div>
                <label for="first_name" class="block text-sm font-medium text-gray-700">First name</label>
                <div class="mt-1">
                  <!-- //////
                  /// Set First Name can only be edit by admin and user concerned
                  /// Default is ENABLE FOR ALL USER
                  /// SUBSECTION STARTS HERE
                  ////// -->
                  <input value="<?= $row['first_name'] ?>" <?= !can_edit_data($row['id']) ? "disabled" : "" ?> placeholder="John" type="text" name="first_name" id="first_name" autocomplete="given-name" class="form-input py-3 px-4 block w-full shadow-sm focus:ring-red-500 focus:border-red-500 border-gray-300 rounded-md">
                  <!-- //////
                  /// SUBSECTION ENDS HERE
                  ////// -->
                </div>
              </div>
              <div>
                <label for="last_name" class="block text-sm font-medium text-gray-700">Last name</label>
                <div class="mt-1">
                  <!-- //////
                  /// Set Last Name can only be edit by admin and user concerned
                  /// Default is ENABLE FOR ALL USER
                  /// SUBSECTION STARTS HERE
                  ////// -->
                  <input value="<?= $row['last_name'] ?>" <?= !can_edit_data($row['id']) ? "disabled" : "" ?> placeholder="Doe" type="text" name="last_name" id="last_name" autocomplete="family-name" class="form-input py-3 px-4 block w-full shadow-sm focus:ring-red-500 focus:border-red-500 border-gray-300 rounded-md">
                  <!-- //////
                  /// SUBSECTION ENDS HERE
                  ////// -->
                </div>
              </div>
              <div class="sm:col-span-2">
                <label for="email" class="block text-sm font-medium text-gray-700">Email</label>
                <div class="mt-1">
                  <input value="<?= $row['email'] ?>" disabled placeholder="Eg. someone@company.com" id="email" name="email" type="email" autocomplete="email" class="form-input py-3 px-4 block w-full shadow-sm focus:ring-red-500 focus:border-red-500 border-gray-300 rounded-md">
                </div>
              </div>
              <div class="sm:col-span-2">
                <label for="phone_number" class="block text-sm font-medium text-gray-700">Phone Number</label>
                <div class="mt-1 rounded-md shadow-sm flex flex-row">
                  <input value="<?= $row['phone_number'] ?>" disabled type="text" pattern="[0-9]*" name="phone_number" id="phone_number" autocomplete="tel" class="form-input py-3 px-4 block w-full pl-20 focus:ring-red-500 focus:border-red-500 border-gray-300 rounded-md" placeholder="08xxxxxxxxx">
                </div>
              </div>
              <div class="sm:col-span-2">
                <label for="gender" class="block text-sm font-medium text-gray-700">Gender</label>
                <div class="mt-1">
                  <!-- //////
                  /// Set Gender can only be edit by admin and user concerned
                  /// Default is ENABLE FOR ALL USER
                  /// SUBSECTION STARTS HERE
                  ////// -->
                  <select name="gender" id="gender" <?= !can_edit_data($row['id']) ? "disabled" : "" ?> class="form-select py-3 px-4 block w-full shadow-sm focus:ring-red-500 focus:border-red-500 border-gray-300 rounded-md">
                    <option value="1" <?= ($row['gender'] == 1) ? "selected" : "" ?>>Male</option>
                    <option value="2" <?= ($row['gender'] == 2) ? "selected" : "" ?>>Female</option>
                  </select>
                  <!-- //////
                  /// SUBSECTION ENDS HERE
                  ////// -->
                </div>
              </div>
              <div class="sm:col-span-2">
                <label for="role" class="block text-sm font-medium text-gray-700">Role</label>
                <div class="mt-1">
                  <!-- //////
                  /// Set Role can only be edit by admin
                  /// Default is ENABLE FOR ALL USER
                  /// SUBSECTION STARTS HERE
                  ////// -->
                  <select name="role" id="role" <?= !($_SESSION['role'] === "admin") ? "disabled" : "" ?> class="form-select py-3 px-4 block w-full shadow-sm focus:ring-red-500 focus:border-red-500 border-gray-300 rounded-md">
                    <option value="member" <?= ($row['role'] === "member") ? "selected" : "" ?>>Member</option>
                    <option value="admin" <?= ($row['role'] === "admin") ? "selected" : "" ?>>Admin</option>
                  </select>
                  <!-- //////
                  /// SUBSECTION ENDS HERE
                  ////// -->
                </div>
              </div>
              <div class="sm:col-span-2">
                <label for="about" class="block text-sm font-medium text-gray-700">About</label>
                <div class="mt-1">
                <!-- //////
                /// Set About can only be edit by admin and user concerned
                /// Default is ENABLE FOR ALL USER
                /// SUBSECTION STARTS HERE
                ////// -->
                <textarea id="about" name="about" placeholder="No description yet.." <?= !can_edit_data($row['id']) ? "disabled" : "" ?> rows="3" class="w-full form-input shadow-sm block w-full focus:ring-red-500 focus:border-red-500 sm:text-sm border-gray-300 rounded-md"><?= $row['about'] ?></textarea>
                <!-- //////
                /// SUBSECTION ENDS HERE
                ////// -->    
                </div>
              </div>
              <!-- //////
              /// Set Update Profile Button only visible to admin and user concerned
              /// Default is ENABLE FOR ALL USER
              /// SUBSECTION STARTS HERE
              ////// -->
              <?php if(can_edit_data($row['id'])){ ?>
                <div class="sm:col-span-2 grid grid-cols-1 md:grid-cols-2 gap-y-2 md:gap-y-0 md:gap-x-2">
                <!--
                //////
                /// QUESTION 5 SECTION 2F OF 3: Cross-Site Request Forgery (CSRF) - Token Field
                /// SECTION STARTS HERE
                //////
                -->
                
                <?= csrf_field() ?>

                <!-- //////
                /// SECTION ENDS HERE
                ////// -->
                  <input type="hidden" name="id" value="<?= $_GET['id'] ?>">
                  <input type="hidden" name="img_status" id="img-status" value="0">
                  <!-- //////
                  /// Set Add/Remove from Blacklist Button only visible to admin
                  /// Default is ENABLE FOR ALL USER
                  /// SUBSECTION STARTS HERE
                  ////// -->
                  <?php if($_SESSION['role'] == 'admin'){ ?>
                    <button type="submit" name="delete" class="col-span-1 inline-flex items-center justify-center bg-white py-3 px-6 border border-gray-300 rounded-md shadow-sm text-sm font-medium text-gray-700 hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-red-500">
                      <?= ($row['deleted_id'] != null) ? 'Remove from Blacklist' : 'Add to Blacklist' ?>
                    </button>
                  <?php } ?>
                  <!-- //////
                  /// SUBSECTION ENDS HERE
                  ////// --> 

                  <!-- //////
                  /// OPTIONAL!!!
                  /// class col-span-1 if logged user is admin, else col-span-2
                  /// Default is col-span-1
                  /// SUBSECTION STARTS HERE
                  ////// -->
                  <button type="submit" name="update" class="<?= ($_SESSION['role'] == 'admin') ? 'col-span-1' : 'col-span-2' ?> inline-flex items-center justify-center px-6 py-3 border border-transparent rounded-md shadow-sm text-base font-medium text-white bg-red-400 hover:bg-red-500 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-red-500">
                    Update Profile
                  </button>
                  <!-- //////
                  /// SUBSECTION ENDS HERE
                  ////// --> 
                </div>
              <?php } ?>
              <div class="sm:col-span-2" style="width: 40rem;">
                
              </div>
            </div>
          </div>
        </div>
      </form>

    </main>
  </div>
  <!-- //////
  /// SUBSECTION ENDS HERE
  ////// -->  
  <?php include('../layouts/footer.php') ?>

</body>

</html>
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
    <script src="../js/page/host/create.js"></script>
</head>
<body class="h-screen flex flex-col justify-between bg-gray-100">
    <?php 
        include('../database/db.php'); 
        include('../helpers/function.php');
    //////
    /// QUESTION 3 SECTION 5 OF 12: Access Control
    /// Validate that only admin can access this page
    /// SECTION STARTS HERE
    //////

        if (!isset($_SESSION['role']) || $_SESSION['role'] !== 'admin'){
            header('location: ../');
            return;
        }
    //////
    /// SECTION ENDS HERE
    //////
    ?>
    <div class="flex flex-col">
        <?php include('../layouts/header.php') ?>
        <main class="max-w-7xl mx-auto px-2 lg:px-8 py-4 space-y-8">
            <div class="text-3xl font-extrabold tracking-tight text-gray-900 sm:text-4xl w-full">
              User List
            </div>
            <form action="" class="w-full">
                <div class="mt-1 flex flex-col sm:flex-row gap-x-2 gap-y-2 flex-1">
                    <input placeholder="Search" id="search" name="s" type="text" class="form-input py-3 px-4 block w-full shadow-sm focus:ring-red-500 focus:border-red-500 border-gray-300 rounded-md">
                    <button type="submit" class="inline-flex items-center justify-center px-6 py-3 border border-transparent rounded-md shadow-sm text-base font-medium text-white bg-red-400 hover:bg-red-500 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-red-500">
                        Search
                    </button>
                </div>
            </form>
            <?php if(isset($_GET['s'])){ ?>
                <div class="text-lg">Search result for <span class="font-bold"><?= htmlspecialchars($_GET['s']) ?></span></div>
            <?php } 
                $search = '';

                if (isset($_GET['s'])){
                $search = "where concat(first_name, ' ', last_name) like '%" . $_GET['s'] . "%' ";
                }

                $sql = "SELECT u.*, d.id as deleted_id FROM users u left join deleteditems d
                on d.data_id = u.id " . $search . "order by first_name";
                $result = $conn->query($sql);
                if ($result->num_rows > 0){
            ?>
            <ul class="w-full grid grid-cols-1 md:grid-cols-2 gap-4 px-2 md:p-0">
                <?php 
                    while($row = $result->fetch_assoc()){
                ?>

                <li class="col-span-1 border-2 border-gray-300 border-dashed rounded-lg p-3 <?= ($row['deleted_id'] != null) ? 'bg-red-200' : 'bg-white'?>">
                    <a href="<?= route('profile/show?id=' . $row['id']) ?>" class="grid grid-cols-4 gap-x-3 items-center">
                        <?php if($row['photo'] !== null){ ?>
                            <img src="<?= route('assets/images/profile/' . $row['photo']) ?>" alt="" class="col-span-1 w-full rounded-full p-2 mx-auto">
                        <?php } else { ?>
                            <svg xmlns="http://www.w3.org/2000/svg" class="col-span-1 w-full text-gray-500 mx-auto" viewBox="0 0 20 20" fill="currentColor">
                                <path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-6-3a2 2 0 11-4 0 2 2 0 014 0zm-2 4a5 5 0 00-4.546 2.916A5.986 5.986 0 0010 16a5.986 5.986 0 004.546-2.084A5 5 0 0010 11z" clip-rule="evenodd" />
                            </svg>
                        <?php } ?>
                        <div class="flex flex-col sm:space-y-3 col-span-3">
                            <div class="flex flex-col">
                                <span class="text-lg sm:text-xl font-medium truncate"><?= $row['first_name'] . ' ' . $row['last_name']?></span>
                            </div>
                            <div class="flex flex-col">
                                <span class="text-sm sm:text-base grid grid-cols-5">
                                    <div class="col-span-2">Email</div>
                                   <span class="col-span-3 font-medium span-start truncate"><?= $row['email'] ?></span>
                                </span> 
                                <span class="text-sm sm:text-base grid grid-cols-5">
                                    <div class="col-span-2">Phone Number</div>
                                    <span class="col-span-3 font-medium span-start"><?= $row['phone_number'] ?></span>
                                </span>
                                <span class="text-sm sm:text-base grid grid-cols-5">
                                    <div class="col-span-2">Gender</div>
                                    <span class="col-span-3 font-medium span-start"><?= ($row['gender'] == 1) ? 'Male' : 'Female' ?></span>
                                </span>
                                <span class="text-sm sm:text-base grid grid-cols-5">
                                    <div class="col-span-2">Role</div>
                                    <span class="col-span-3 font-medium span-start"><?= ucfirst($row['role']) ?></span>
                                </span>
                            </div>
                        </div>
                    </a>
                </li>

                <?php } ?>
            </ul>

            <?php } else { ?>
                <div>No user found with this keyword, maybe you can try with another keyword!</div>
            <?php } ?>
        </main>
    </div>
    <?php include('../layouts/footer.php') ?>

</body>

</html>
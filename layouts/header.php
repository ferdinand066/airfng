<!-- This example requires Tailwind CSS v2.0+ -->
<nav class="bg-gray-50 shadow">
  <div class="max-w-7xl mx-auto px-2 sm:px-6 lg:px-8">
    <div class="flex flex-row justify-between py-4">
        <div class="flex flex-row items-center text-center space-x-2">
            <img src="<?= route('assets/images/airfng.png') ?>" alt="" class="w-10 h-10">
            <a href="<?= route('') ?>" class="flex justify-center items-center text-2xl brown text-red-400 font-bold">airfng</a>
        </div>
        <div class="flex flex-row space-x-4 items-center">
            <a href="<?= route('host/create') ?>" class="font-medium hidden sm:block">Become a Host</a>
            <div class="relative cursor-pointer">
                <div class="flex flex-row space-x-2 items-center pl-3 pr-2 py-0.5 border-2 rounded-full text-gray-300 hover:shadow-md">
                    <svg id="btn-menu" xmlns="http://www.w3.org/2000/svg" class="w-6 h-6 text-gray-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16" />
                    </svg>
                    <?php if(isset($_SESSION['photo']) && $_SESSION['photo'] !== null){ ?>
                        <img id="profile-picture" src="<?= route('assets/images/profile/' . $_SESSION['photo']) ?>" alt="" class="w-10 h-10 rounded-full p-0.5">
                    <?php } else { ?>
                        <svg id="profile-picture" xmlns="http://www.w3.org/2000/svg" class="w-10 h-10 text-gray-500" viewBox="0 0 20 20" fill="currentColor">
                            <path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-6-3a2 2 0 11-4 0 2 2 0 014 0zm-2 4a5 5 0 00-4.546 2.916A5.986 5.986 0 0010 16a5.986 5.986 0 004.546-2.084A5 5 0 0010 11z" clip-rule="evenodd" />
                        </svg>
                    <?php } ?>
                </div>
                <!-- //////
                /// QUESTION 3 SECTION 11 OF 12: Access Control
                /// Validate button at navigation bar visible based on user's login status
                /// SECTION STARTS HERE
                ////// -->

                <!-- //////
                /// OPTIONAL!!!
                /// class w-64 logged user is admin, else w-52
                /// Default is w-64
                /// SUBSECTION STARTS HERE
                ////// -->
                <div id="nav-profile-dropdown" class="hidden z-20 absolute right-0 top-14 divide-y <?= isset($_SESSION['id']) ? 'w-64' : 'w-52' ?> rounded-md shadow-md bg-white">
                <!-- //////
                /// SUBSECTION ENDS HERE
                ////// -->  
                
                    <!-- //////
                    /// Visible profile submenu only for logged user
                    /// Visible login and signup menu only for guest
                    /// Default is ENABLE FOR ALL USER
                    /// SUBSECTION STARTS HERE
                    ////// -->    
                    <?php if (isset($_SESSION['id'])){ ?>
                        <a href="<?= route('profile/show?id=' . $_SESSION['id']) ?>" class="flex flex-row w-full space-x-2 px-2 py-2">
                            <?php if($_SESSION['photo'] !== null){ ?>
                                <img src="<?= route('assets/images/profile/' . $_SESSION['photo']) ?>" alt="" class="w-16 h-16 rounded-full p-1">
                            <?php } else { ?>
                                <svg xmlns="http://www.w3.org/2000/svg" class="w-16 h-16 text-gray-500" viewBox="0 0 20 20" fill="currentColor">
                                    <path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-6-3a2 2 0 11-4 0 2 2 0 014 0zm-2 4a5 5 0 00-4.546 2.916A5.986 5.986 0 0010 16a5.986 5.986 0 004.546-2.084A5 5 0 0010 11z" clip-rule="evenodd" />
                                </svg>
                            <?php } ?>
                            <div class="flex flex-col my-auto flex-1 truncate">
                                <span class="font-medium truncate"><?= $_SESSION['first_name'] ?></span>
                                <span><?= ucwords($_SESSION['role']) ?></span>
                            </div>
                        </a>
                        <div class="flex flex-col w-full">
                            <a href="<?= route('transaction') ?>" class="px-4 py-2 hover:bg-gray-50">View transaction</a>
                            <!-- //////
                            /// Visible user list menu only for admin
                            /// Default is ENABLE FOR ALL USER
                            /// SUBSECTION STARTS HERE
                            ////// -->  
                            <?php if($_SESSION['role'] === 'admin'){ ?>
                                <a href="<?= route('profile') ?>" class="px-4 py-2 hover:bg-gray-50">User list</a>
                            <?php } ?>
                            <!-- //////
                            /// SUBSECTION ENDS HERE
                            ////// -->   
                        </div>

                    <?php } else { ?>
                        <div class="flex flex-col w-full">
                            <a href="<?= route('auth/login') ?>" class="px-4 py-2 hover:bg-gray-50 rounded-t-md">Login</a>
                            <a href="<?= route('auth/signup') ?>" class="px-4 py-2 hover:bg-gray-50">Sign Up</a>
                        </div>
                    <?php } ?>
                    <!-- //////
                    /// SUBSECTION ENDS HERE
                    ////// --> 
                    <div class="flex flex-col w-full">
                        <a href="<?= route('host/create') ?>" class="px-4 py-2 hover:bg-gray-50 <?= isset($_SESSION['id']) ? '' : 'rounded-b-md' ?>">Host your home</a>
                    </div>
                    <!-- //////
                    /// Visible logout menu only for logged user
                    /// Default is ENABLE FOR ALL USER
                    /// SUBSECTION STARTS HERE
                    ////// -->   
                    <?php if (isset($_SESSION['id'])){ ?>
                        <div class="flex flex-col w-full">
                            <a href="<?= route('controllers/auth/LogoutController') ?>" class="px-4 py-2 hover:bg-gray-50 rounded-b-md">Logout</a>
                        </div>
                    <?php } ?>

                    <!-- //////
                    /// SUBSECTION ENDS HERE
                    ////// --> 


                    <!-- //////
                    /// SECTION ENDS HERE
                    ////// -->
                </div>
            </div>
        </div>
    </div>
  </div>
</nav>

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
    <script src="../js/layout/notification.js"></script>
    <script src="../js/layout/layout.js"></script>
    <script src="../js/page/host/create.js"></script>
</head>
<body class="h-screen flex flex-col justify-between bg-gray-100">
    <?php 
        include('../database/db.php'); 
        include('../helpers/function.php');
        ?>
    <div class="flex flex-col">
        <?php include('../layouts/header.php') ?>
        <main class="max-w-7xl mx-auto px-2 lg:px-8 py-4 space-y-8">
            <ul class="w-full grid grid-cols-1 md:grid-cols-2 gap-4 px-2 md:p-0">
                <?php 
                    $condition = '';
                    if (isset($_GET['city_id'])){   
                        $condition = "WHERE c.id = '" . $_GET['city_id'] . "'";
                    }
                    $sql = "SELECT h.*, c.name as city_name FROM hosts h join cities c on h.city_id = c.id $condition order by h.name";
                    $result = $conn->query($sql);
                    if ($result->num_rows < 1){
                        header('location: ../');
                        return;
                    }
                    while($row = $result->fetch_assoc()){
                ?>

                <li class="col-span-1 border-2 border-gray-300 border-dashed rounded-lg bg-white grid items-center">
                    <a href="<?= route('host/show?id=' . $row['id'] )?>" class="grid grid-cols-5 gap-x-3 items-center gap-y-2 p-3">
                        <img src="<?= route('assets/images/host/' . $row['photo']) ?>" alt="<?= $row['name'] ?>" class="col-span-5 md:col-span-2 h-40 w-64 rounded-lg object-cover mx-auto md:mx-0" >
                        <div class="flex flex-col sm:space-y-3 col-span-5 md:col-span-3">
                            <div class="flex flex-col">
                                <span><?= $row['city_name'] ?></span>
                                <span class="text-lg sm:text-xl font-medium line-clamp"><?= $row['name'] ?></span>
                            </div>
                            <div class="line-clamp">
                                <?php
                                    $data = json_decode($row['rooms']);
                                    $total = count($data);
                                    $i = 0;
                                    foreach($data as $key => $value){ ?>
                                        <span class="text-sm"><?= $value->quantity . ' ' . $value->room_name . (($i !== $total - 1)
                                            ? ' - ' : '') ?></span>
                                <?php $i++;} ?>
                            </div>
                            <span class="sm:text-lg"><span class="font-medium">$<?=  $row['price'] ?></span> / night</span>
                        </div>
                    </a>
                </li>

                <?php } ?>
            </ul>
        </main>
    </div>
    <?php include('../layouts/footer.php') ?>

</body>

</html>
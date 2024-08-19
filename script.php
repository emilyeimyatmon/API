<?php
session_start();
include('includes/config.php');
error_reporting(0);

// Google Safe Browsing API key
$apiKey = 'AIzaSyD2PLhJ90WjaywCOBTKCynUQqvBbKThMGI';

// Function to check URL with Google Safe Browsing API
function checkUrlWithGoogleSafeBrowsing($url, $apiKey) {
    $apiUrl = 'https://safebrowsing.googleapis.com/v4/threatMatches:find?key=' . $apiKey;
    
    $postData = json_encode([
        'client' => [
            'clientId' => 'yourcompany',
            'clientVersion' => '1.0.0'
        ],
        'threatInfo' => [
            'threatTypes' => ['MALWARE', 'SOCIAL_ENGINEERING'],
            'platformTypes' => ['ANY_PLATFORM'],
            'threatEntryTypes' => ['URL'],
            'threatEntries' => [['url' => $url]]
        ]
    ]);
    
    $ch = curl_init($apiUrl);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $postData);
    curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);
    
    $response = curl_exec($ch);
    curl_close($ch);
    
    return json_decode($response, true);
}

// Function to check URL with APIVoid
function checkApiVoid($url) {
    $apivoid_key = "a10f59324eea824e56d07248b704c05dff60c7fa";
    $curl = curl_init("https://endpoint.apivoid.com/urlrep/v1/pay-as-you-go/?key=".$apivoid_key."&url=".urlencode($url));
    curl_setopt($curl, CURLOPT_RETURNTRANSFER, 1);
    $output = curl_exec($curl);
    curl_close($curl);
                                    
    return json_decode($output, true);
}

// Function to check if the URL is in the phishing list and retrieve all associated data
function getPhishingData($url, $phishingList) {
    foreach ($phishingList as $entry) {
        if ($entry['url'] === $url) {
            return $entry; // Return the entire data for the matching URL
        }
    }
    return null;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    header('Content-Type: application/json');

    // Get and sanitize the URL from the POST request
    $inputUrl = filter_var($_POST['url'], FILTER_SANITIZE_URL);
    
    // Validate the URL format
    if (filter_var($inputUrl, FILTER_VALIDATE_URL) === false) {
        echo json_encode(['error' => 'Invalid URL format.']);
        exit;
    }

    $foundPhishing = false;
    $response = [];

    // Check URL with Google Safe Browsing API
    $googleSafeBrowsingData = checkUrlWithGoogleSafeBrowsing($inputUrl, $apiKey);
    if (isset($googleSafeBrowsingData['matches'])) {
        $response[] = [
            'source' => 'Google Safe Browsing',
            'result' => 'phishing',
            'details' => $googleSafeBrowsingData
        ];
        $foundPhishing = true;
    }

    // Check URL with APIVoid
    if (!$foundPhishing) {
        $apiVoidResult = checkApiVoid($inputUrl);
        if ($apiVoidResult && isset($apiVoidResult['data']['report']['risk_score']['result']) && intval($apiVoidResult['data']['report']['risk_score']['result']) >= 70) {
            $response[] = [
                'source' => 'APIVoid',
                'result' => 'phishing',
                'details' => $apiVoidResult
            ];
            $foundPhishing = true;
        }
    }

    // Check phishing JSON file
    if (!$foundPhishing) {
        $phishingJsonFile = '../file.json';
        $phishingJsonData = file_get_contents($phishingJsonFile);
        $phishingData = json_decode($phishingJsonData, true);

        if (json_last_error() !== JSON_ERROR_NONE) {
            echo json_encode(['error' => 'Error parsing phishing JSON: ' . json_last_error_msg()]);
            exit;
        }

        $phishingDetails = getPhishingData($inputUrl, $phishingData);
        if ($phishingDetails) {
            $response[] = [
                'source' => 'Phishing Tank',
                'result' => 'phishing',
                'details' => $phishingDetails
            ];
            $foundPhishing = true;
        }
    }

    // Check local database
    if (!$foundPhishing) {
        $sql = "SELECT * FROM url WHERE url = :inputUrl";
        $query = $dbh->prepare($sql);
        $query->bindParam(':inputUrl', $inputUrl, PDO::PARAM_STR);
        $query->execute();
        $results = $query->fetchAll(PDO::FETCH_OBJ);

        if ($query->rowCount() > 0) {
            foreach ($results as $output) {
                if ($output->result == 1) { // Assuming 'result' is the field that flags phishing
                    $response[] = [
                        'source' => 'Local Database',
                        'result' => 'phishing',
                        'details' => $output
                    ];
                    $foundPhishing = true;
                } else {
                    $response[] = [
                        'source' => 'Local Database',
                        'result' => 'safe',
                        'details' => $output
                    ];
                }
            }
        } else {
            $response[] = [
                'source' => 'Local Database',
                'result' => 'safe',
                'details' => 'URL not found in local database.'
            ];
        }
    }

    // Return the response as JSON
    echo json_encode($response);
}
?>

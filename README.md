# AuthMatrix v0.6.0

AuthMatrix is an extension to Burp Suite that provides a simple way to test authorization in web applications and web services. With AuthMatrix, testers focus on thoroughly defining tables of users, roles, and requests for their specific target application upfront. These tables are displayed through the UI in a similar format to that of an access control matrix common in various threat modeling methodologies.

Once the tables have been assembled, testers can use the simple click-to-run interface to kick off all combinations of roles and requests. The results can be confirmed with an easy to read, color-coded interface indicating any authorization vulnerabilities detected in the system. Additionally, the extension provides the ability to save and load target configurations for simple regression testing.

# Installation

AuthMatrix can be installed through the Burp Suite BApp Store. From within Burp Suite, select the Extender tab, select the BApp Store, select AuthMatrix, and click install.

For Manual installation, download AuthMatrix.py from this repository.  Then from within Burp Suite, select the Extender tab, click the Add button, change the Extension type to Python, and select the AuthMatrix python file.

### Note

AuthMatrix requires configuring Burp Suite to use Jython.  Easy instructions for this are located at the following URL.

https://portswigger.net/burp/help/extender.html#options_pythonenv

Be sure to use Jython version 2.7.0 or greater to ensure compatibility.

# Basic Usage

1. Create roles for all privilege levels within the target application.  (Common roles may include User, Admin, and Anonymous)

2. Create enough users to fit these various roles and select the checkboxes for all roles that the user belongs to.

3. From another area of Burp Suite (i.e. Target tab, Repeater Tab, etc) right click a request and select "Send to AuthMatrix." 

4. In the second table of AuthMatrix, select the checkboxes for all roles that are authorized to make each HTTP request.

5. Create a Response Regex based on the expected response behavior of the request to determine if the action has succeeded. 

  * Common regexes include HTTP Response headers, success messages within the body, or other variations within the body of the page.

  * NOTE: Messages can be configured to use a Failure Regex instead through the right-click menu (i.e. Anonymous should never receive an HTTP 200)

6. Generate session tokens for each user from the Repeater tab and enter them into the relevant column within the first table (Cookies, HTTP Header, HTTP Parameter).

  * If the target uses static CSRF tokens, place these into the HTTP Parameter column

  * NOTE: Multiple cookies can be added using a ";" seperator. Currently, only one HTTP Header or HTTP Parameter is supported.


7. Click Run at the bottom to run all requests or right click several messages and select run.  Observe that the adjacent table will show color-coded results.

  * Green indicates no vulnerability detected

  * Red indicates the request may contain a vulnerability

  * Blue indicates that the result may be a false positive.  (This generally means there is an invalid/expired session token or an incorrect regex)

# Advanced Usage (Chains)

TODO

## Sample AuthMatrix Configuration

![Sample AuthMatrix Configuration]
(img1.png)

## Sample Configuration with Failure Regex Mode

![Sample Configuration with Failure Regex Mode]
(img2.png)


## Invalid AuthMatrix Configuration (False Positives Detected)

![Invalid AuthMatrix Configuration]
(img3.png)


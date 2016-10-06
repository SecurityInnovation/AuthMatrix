# AuthMatrix v0.6.0

AuthMatrix is an extension to Burp Suite that provides a simple way to test authorization in web applications and web services. With AuthMatrix, testers focus on thoroughly defining tables of users, roles, and requests for their specific target application upfront. These tables are displayed through the UI in a similar format to that of an access control matrix commonly built in various threat modeling methodologies.

Once the tables have been assembled, testers can use the simple click-to-run interface to efficiently run all combinations of roles and requests. Testers can then confirm their results with an easy to read, color-coded interface indicating any authorization vulnerabilities detected in the system. Additionally, the extension provides the ability to save and load target configurations for simple regression testing.

# Installation

AuthMatrix can be easily installed through the Burp Suite BApp Store. From within Burp Suite, select the Extender tab, select the BApp Store, select AuthMatrix and click install.

For Manual installation, download AuthMatrix.py from this repository.  Then from within Burp Suite, select the Extender tab, click the Add button, change the Extension type to Python and select the AuthMatrix python file.

### Note

AuthMatrix requires configuring Burp Suite to use Jython.  Easy instructions for this can be located at the following URL.

https://portswigger.net/burp/help/extender.html#options_pythonenv

Be sure to use Jython version 2.7.0 or greater to ensure compatibility.

# Usage

* In AuthMatrix, create roles for all privilege levels within the target application.  Common roles may include User, Admin, and Anonymous.

* Create users that fit these various roles and check all roles that the user belongs to.  If a user is part of multiple roles, check each role individually.

* From another area of Burp Suite (i.e. Target tab, Repeater Tab, etc) right click a request and select "Send to AuthMatrix." This will create a new item in the second table of the interface.  Multiple requests can be added all at once by selecting several requests from within the Target tab.

* In the second table of AuthMatrix, check all roles that are authorized to make each request.

* Create a regex based on the expected response behavior of the request to determine if the action has succeeded. Common regexes include HTTP Response headers, success messages within the body, or other variations within the body of the page.

* Generate session tokens for each user via a web browser or the repeater tab and enter them into the correct field within the first table.

* OPTIONAL: If the target application uses user-specific reusable CSRF tokens, enter them into the correct field within the first table. Advanced CSRF protection handling is not currently supported in AuthMatrix.

* Click Run to run all requests or right click several messages and select run.  Observe that the adjacent table will show color-coded results

  * Green indicates the request returned expected results

  * Red indicates the request did not return expected results and may contain a vulnerability

  * Orange indicates that the result may be a false positive.  This generally means there is an invalid/expired session token or an incorrect success regex.

## Sample AuthMatrix Configuration

![Sample AuthMatrix Configuration]
(img1.png)

## Sample Configuration with Failure Regex Mode

![Sample Configuration with Failure Regex Mode]
(img2.png)


## Invalid AuthMatrix Configuration (False Positives Detected)

![Invalid AuthMatrix Configuration]
(img3.png)


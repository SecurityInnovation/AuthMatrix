AuthMatrix v0.3

AuthMatrix is an extension the Burp Suite that provides a simple way to test authorization in web applications and web services.  It differentiates itself from several current auth testing extensions in that it focuses on the Pentester thoroughly defining tables of Users, Roles, and Requests for the specific target application. These tables are displayed in the UI in a similar format to access control matricies common in various threat modeling techniques. 

Once the tables have been assembled, users can use the simple click-to-run interface to efficiently test all combinations of roles and displays easy to read results indicating any authorization vulnerabilities detected in the system.  

AuthMatrix is designed with an intuitive UI to make authorization testing simple and easy to integrate into your current testing methodology. The extension provides the ability to save target configurations for easy regression testing. 

# Installation

AuthMatrix can be simply installed through the Burp Suite BApp Store. From within Burp Suite, select the Extender tab, select the BApp Store, select AuthMatrix and install.

For Manual installation, download AuthMatrix.py from this repository.  The from within Burp Suite, select the Extender tab, click the Add button, change the Extension type to Python and select the python file.

* Note

AuthMatrix requires configuring Burp Suite to use Jython.  Easy instructions for this can be found at the following URL.

https://portswigger.net/burp/help/extender.html#options_pythonenv

# Usage

* In AuthMatrix, Create Roles for all privilege levels within the target application.  Common Roles include User, Admin, and Anonymous

* Create Users that fit these various Roles and check all that apply.  If a user is part of multiple Roles, check each Role.

* From another area of Burp Suite (ie Target tab, Repeater Tab, etc) right click a request and select "Send to AuthMatrix." This will create a new item in the second table of the interface.  Multiple requests can be added at once from within the Target tab.

* In the second table of AuthMatrix, check all Roles that are authorized to make the request.

* Create a regex based on the expected response behavior of the request to determine if the request has suceeded. Common regexes include HTTP Response headers, success messages within the body, or other variations within the page.

* Generate session tokens for each User and enter them into field within the first table.

* OPTIONAL: If the target application uses user-specific reusable CSRF tokens, enter them into the correct field within the first table.

* Click Run to run all requests or right click several messages and select run.  Observe that the adjacent table will show color coded results, red indicating the request did not return expected results and may indicate a vulnerability.

 
# AuthMatrix v0.6.3

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

  * NOTE: Multiple cookies can be added using a ";" separator. Currently, only one HTTP Header or HTTP Parameter is supported.


7. Click Run at the bottom to run all requests or right click several messages and select run.  Observe that the adjacent table will show color-coded results.

  * Green indicates no vulnerability detected

  * Red indicates the request may contain a vulnerability

  * Blue indicates that the result may be a false positive.  (This generally means there is an invalid/expired session token or an incorrect regex)

## Sample AuthMatrix Configuration

![Sample AuthMatrix Configuration](images/img1.png)


## False Positives Detected (Invalid Session Tokens)

![Invalid Session Tokens](images/img2.png)

# Advanced Usage

## Failure Regex Mode

For certain targets, it may be easier to configure AuthMatrix to detect the response condition of when a request has failed. For example, if a target site returns unique data on successful requests, but always returns an HTTP 303 when an unauthorized action is performed. In this mode, AuthMatrix will validate this regex for all users not part of a succeeding role.

To do this, right click the request and select "Toggle Regex Mode".  The regex field will be highlighted in purple to indicate that AuthMatrix will run the request in Failure Regex Mode.

__NOTE:__ False positive detection and highlighting may not work in Failure Regex Mode

## Sample Configuration with Failure Regex Mode

![Sample Configuration with Failure Regex Mode](images/img3.png)

## Chains

Chains provide a way to copy a value from the response of one request to the body of another request.

The most common use cases for this are:

1. Copying CSRF Tokens over when a target generates new user-specific tokens with each request

2. Testing newly created IDs/GUIDs for authorization issues

A Chain entry has the following values:

* __Enabled:__ a checkbox to enable/disable the chain (useful for debugging)

* __Chain Name:__ a descriptive name

* __SRC - Message ID:__ The message ID of the source request in the message table

* __SRC - User ID:__ (OPTIONAL) The source user for Pitchfork Mode (See Below)

* __SRC - Regex:__ a regex used to extract a value from the response of the source message.  This must contain one parenthesis grouping that is to be extracted [i.e. (.*)]

* __DEST - Message ID(s):__ a list of message IDs for the destination requests that the source value will be replaced into.  Can contain numbers, commas, and/or dashes to indicate a range.

* __DEST - Regex:__ a regex used to determine where the extracted value is to be inserted.  This must contain one parenthesis grouping to be replaced [i.e. (.*)]

__NOTE:__ Messages are run in order of row, so the destination messages must be listed after the source message in order to successfully replace the value.  Messages can be moved in the table by selecting and dragging the entry.

## Chains - Pitchfork Mode

There are two modes in which chains can be used: Standard and Pitchfork

__Standard Mode:__ A source value will be collected for each user and then placed into that corresponding user's message body.  This is most useful for CSRF, since these tokens will be user specific.  Chains in this mode do not directly test authorization, but may be useful in order to run an AuthMatrix configuration successfully.  To set a chain to Standard Mode, leave the **SRC - User ID** field empty. 

__Pitchfork Mode:__ The source value is extracted from the response for only one selected user and is then inserted into the requests of all users.  This is most useful to test new authorization cases where an identifier must only accessible to only that one specific user. Pitchfork Mode is enabled by selecting the User ID of the user whose response value is to be propagated.

## Chains for Advanced CSRF

![Chain for CSRF](images/img5.png)

## Chain for New Identifiers (Pitchfork Mode)

![Chain Pitchfork](images/img6.png)


## State Files

State files are saved as JSON strings. 

This document describes each field of this file so that power users can automate tasks by modifying state files directly.

Note that several fields are only used internally and can safely be ignored when constructing state by hand.

Additionally, several fields are base64 encoded.  This is done to simplify the process of parsing JSON (such as removing comments)

Several fields reference identifiers of other elements (i.e. Users reference Roles by their index). For these cases, it may not be possible to locate the index from the UI.  It may be necessary to parse an existing state to determine what existing elements map to which identifiers.

## JSON Format

    {
        /**
          * String indicating version of AuthMatrix this state file corresponds with
          * @required
          * @type String
          */
        "version": "0.8",
        
        /**
          * Array containing 0 or more Role objects
          * @optional: if omitted, the existing roles are unchanged
          * @type Array
          */
        "arrayOfRoles": [
            {
                /**
                  * Internal ID of this Role
                  * @required
                  * @condition All IDs for a given type must be unique
                  * @condition IDs for a given type must start from 0
                  * @condition All elements must be listed in order by index and increment by 1
                  * @type int
                  */
                "index": 0,
    
                /**
                  * Which column this role is displayed in
                  * @required
                  * @condition All non-deleted columns for a given type must be unique
                  * @condition Non-deleted columns must be between 0 and the amount of non-deleted elements
                  * @type int
                  */
                "column": 0,
    
                /**
                  * Name of the Role
                  * @required
                  * @condition All non-deleted elements in arrayOfRoles must have different names
                  * @type String
                  */
                "name": "Admins",
    
                /**
                  * Indicates whether this Role has been deleted
                  * @optional default=false
                  * @type Bool
                  */
                "deleted": false,
    
                /**
                  * Indicates whether this is a Single User role
                  * @optional default=false
                  * @type Bool
                  */
                "singleUser": false
            }
        ],
        /**
          * Array containing 0 or more Users
          * @optional: if omitted, the existing Users Table is unchanged
          * @type Array
          */
        "arrayOfUsers": [
            {
                /**
                  * Internal ID of this User
                  * @required
                  * @condition All IDs for a given type must be unique
                  * @condition IDs for a given type must start from 0
                  * @condition All elements must be listed in order by index and increment by 1
                  * @type int
                  */
                "index": 0,
    
                /**
                  * Which row of the table this User is displayed in
                  * @required
                  * @condition All non-deleted rows for a given type must be unique
                  * @condition Non-deleted row must be between 0 and the amount of non-deleted elements
                  * @type int
                  */
                "tableRow": 0,
    
                /**
                  * Name of the User
                  * @required
                  * @condition All non-deleted elements in arrayOfUsers must have different names
                  * @type String
                  */
                "name": "admin123",
    
                /**
                  * Map of keys and values, keys = Role Index, value = Bool indicating whether this User belonds to the role
                  * @required
                  * @condition All Role IDs must be included in this map
                  * @type map(str, bool)
                  */
                "roles": {
                    "0": true
                },
    
                /**
                  * Indicates whether this User has been deleted
                  * @optional default=false
                  * @type Bool
                  */
                "deleted": false,
    
                /**
                  * Indicates whether this User is enabled
                  * @optional default=true
                  * @type Bool
                  */
                "enabled": true,
    
                /**
                  * Value of the Cookies field for this User
                  * @optional default=""
                  * @type Base64EncodedString
                  */
                "cookiesBase64": "c2Vzc2lvbl9pZD1hc2Rm",
    
                /**
                  * Array of custom headers for this User
                  * @optional default = []
                  * @condition All users must have the same length array of headersBase64 items
                  * @type ArrayOfBase64EncodedStrings
                  */
                "headersBase64": [
                    "QXV0aG9yaXphdGlvbjogYXNkZg=="
                ],
    
                /**
                  * Internal field
                  * Ignored during Load
                  * @optional
                  */
                "chainResults": {}
            }
        ],
        /**
          * Array containing 0 or more Requests (Messages)
          * @optional: if omitted, the existing Message Table is unchanged
          * @type Array
          */
        "arrayOfMessages": [
            {
                /**
                  * Internal ID of this Message
                  * @required
                  * @condition All IDs for a given type must be unique
                  * @condition IDs for a given type must start from 0
                  * @condition All elements must be listed in order by index and increment by 1
                  * @type int
                  */
                "index": 0,
    
                /**
                  * Which row of the table this Message is displayed in
                  * @required
                  * @condition All non-deleted rows for a given type must be unique
                  * @condition Non-deleted row must be between 0 and the amount of non-deleted elements
                  * @type int
                  */
                "tableRow": 0,
    
                /**
                  * Friendly Name of the Message
                  * @required
                  * @condition All non-deleted elements in arrayOfMessages must have different names
                  * @type String
                  */
                "name": "GET /HumanResources/admin/users",
    
                /**
                  * Map of keys and values, keys = Role Index, value = Bool indicating whether this Message should succeed for this Role
                  * @required
                  * @condition All Role IDs must be included in this map
                  * @type map(str,bool)
                  */
                "roles": {
                    "0": true
                },
    
                /**
                  * Message Body
                  * @required
                  * @type Base64EncodedString
                  */
                "requestBase64": "R0VUIC9IdW1hblJlc291cmNlcy9hZG1pbi91c2VycyBIVFRQLzEuMQ0KSG9zdDogd3d3LnNlY3VyaXR5aW5ub3ZhdGlvbi5jb20KQWNjZXB0OiB0ZXh0L2h0bWwsYXBwbGljYXRpb24veGh0bWwreG1sLGFwcGxpY2F0aW9uL3htbDtxPTAuOSwqLyo7cT0wLjgNCkFjY2VwdC1MYW5ndWFnZTogZW4tVVMsZW47cT0wLjUNCkFjY2VwdC1FbmNvZGluZzogZ3ppcCwgZGVmbGF0ZQ0KQ29ubmVjdGlvbjogY2xvc2UNCgo==",
    
                /**
                  * HTTP Protocol
                  * @required
                  * @type string[http|https]
                  */            
                "protocol": "http",
    
                /**
                  * TCP Port of target
                  * @required
                  * @type int[1-65535]
                  */
                "port": 80,
    
                /**
                  * Domain of target
                  * @required
                  * @type string
                  */
                "host": "www.securityinnovation.com",
    
                /**
                  * Indicates whether this Message has been deleted
                  * @optional default=false
                  * @type Bool
                  */
                "deleted": false,
                
                /**
                  * Indicates whether this Message is enabled
                  * @optional default=true
                  * @type Bool
                  */
                "enabled": true,
                
                /**
                  * Success Regex Field for Message
                  * @optional default=""
                  * @type Base64EncodedString
                  */
                "regexBase64": "XkhUVFAvMVwuMSAyMDAgT0s=",
                
                /**
                  * Indicates whether this Message is using Failure Regex Mode
                  * @optional default=false
                  * @type Bool
                  */
                "failureRegexMode": false,
    
                /**
                  * Internal field
                  * Ignored during Load
                  * @optional
                  * @note This can be queried from Saved States to programatically retrieve the results of a run
                  */
                "runResultForRoleID": {},
                
                /**
                  * Internal field
                  * Ignored during Load
                  * @optional
                  */
                "runBase64ForUserID": {}
            }
        ],
        /**
          * Array containing 0 or more Chains
          * @optional: if omitted, the existing Chain Table is unchanged
          * @type Array
          */
        "arrayOfChains": [
            {
                /**
                  * Internal ID of this Chain
                  * @required
                  * @condition All IDs for a given type must be unique
                  * @condition IDs for a given type must start from 0
                  * @condition All elements must be listed in order by index and increment by 1
                  * @type int
                  */
                "index": 0,
    
                /**
                  * Which row of the table this Chain is displayed in
                  * @required
                  * @condition All non-deleted rows for a given type must be unique
                  * @condition Non-deleted row must be between 0 and the amount of non-deleted elements
                  * @type int
                  */
                "tableRow": 0,
    
                /**
                  * Friendly Name of the Chain
                  * @optional default=""
                  * @type String
                  */
                "name": "CSRF",
    
                /**
                  * Indicates whether this Chain has been deleted
                  * @optional default=false
                  * @type Bool
                  */
                "deleted": false,
    
                /**
                  * Indicates whether this Chain is enabled
                  * @optional default=true
                  * @type Bool
                  */
                "enabled": true,
                
                /**
                  * Source of the Chain
                  * Either the Message ID or the name of the chain prefixed with "SV_"
                  * @optional default=""
                  * @type String
                  */
                "fromID": "SV_CsrfToken",
                
                /**
                  * Source Regex
                  * @optional default=""
                  * @type Base64EncodedString
                  */
                "fromRegexBase64": "PG5hbWU9ImNzcmZUb2tlbiIgdmFsdWU9IiguKj8pIiAvPg==",
                
                /**
                  * Range of Message IDs that represent Destinations
                  * @optional default=""
                  * @type String
                  */
                "toID": "0-2",
                
                /**
                  * Destination Regex
                  * @optional default=""
                  * @type Base64EncodedString
                  */
                "toRegexBase64": "Y3NyZlRva2VuPSguKj8pJg==",
                
                /**
                  * User Values From field of Chain table
                  * Either the index of the User, or -1 to indicate All Users
                  * Optional default=-1
                  * @type int
                  */ 
                "sourceUser": -1,
    
                /**
                  * Ordered array of transformers applied to chain
                  * @optional default=[]
                  * @type ArrayOfStrings
                  */ 
                "transformers": ["base64","url"],
    
                /**
                  * Internal field
                  * Ignored during Load
                  * @optional
                  */
                "fromEnd": "",
    
                /**
                  * Internal field
                  * Ignored during Load
                  * @optional
                  */
                "fromStart": "",
    
                /**
                  * Internal field
                  * Ignored during Load
                  * @optional
                  */
                "toStart": "",
    
                /**
                  * Internal field
                  * Ignored during Load
                  * @optional
                  */
                "toEnd": ""
            }
        ],
        /**
          * Array containing 0 or more ChainSources
          * This is only loaded when an "arrayOfUsers" is also present
          * @optional: if omitted and "arrayOfUsers" is present, defaults to []
          * @type Array
          */
        "arrayOfChainSources": [
            {
                /**
                  * Name of the ChainSource
                  * @required
                  * @condition All ChainSource elements must have different names
                  * @type String
                  */
                "name": "CsrfToken",
    
                /**
                  * Map of keys and values, keys = User Index, value = Chain Source value
                  * @required
                  * @type map(str,str)
                  */
                "userValues": {
                    "0": "asdf"
                }
            }
        ]
    }

## Partial States

If any of the top-level arrays are missing, the associated tables will be unchanged during load.  

This is to enable users who want to update just one table of a configuration to do so with a minimized state file.

## Example: Update User Cookies

    {
        "version": "0.8",
        "arrayOfUsers": [
            {
                "name": "user123",
                "index": 0,
                "tableRow": 0,
                "cookiesBase64": "c2Vzc2lvbl9pZD1hc2Rm",
                "headersBase64": [
                    "QXV0aG9yaXphdGlvbjogYXNkZg=="
                ],
                "roles": {
                    "0": true,
                    "1": false
                }
            },
            {
                "name": "admin123",
                "index": 1,
                "tableRow": 1,
                "cookiesBase64": "c2Vzc2lvbl9pZD1hc2Rm",
                "headersBase64": [
                    "QXV0aG9yaXphdGlvbjogYXNkZg=="
                ],
                "roles": {
                    "0": false,
                    "1": true
                }
            }
        ]
    }

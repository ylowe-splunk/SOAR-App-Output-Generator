from io import StringIO
from datetime import datetime
from pprint import pprint

import sys

'''
Abstract  : Takes string representing a data type, and formats it into the output blocks expected by appname.json
Input     : A string
Output    : A formatted string
'''
def cleanDatatypes(str):
    return (str.replace("datetime", "str")
            .replace("str", "string")
            .replace("int", "numeric")
            .replace("bool", "boolean"))

'''
Abstract  : Takes a nested JSON file and extracts key paths and values in a list
Input     : A nested JSON file
Output    : A list of tuples in the form (key path, value) 
'''
def extractKeyPaths (object, keyArray=[], path=''):
    assert type(object) is dict
    for key in object.keys():
        if type(object[key]) is dict: 
            keyArray = extractKeyPaths(object[key], keyArray, path+str(key)+".")
        elif type(object[key]) is list:
            for count, item in enumerate(object[key]):
                if type(item) is str:   keyArray.append(((path + key + "." + str(count)).replace(' ', '_'), cleanDatatypes(type(item).__name__)))
                if type(item) is dict:  keyArray = extractKeyPaths(item, keyArray, path + str(key) + ".*.")
        else: keyArray.append(((path + key).replace(' ', '_'), cleanDatatypes(type(object[key]).__name__)))
    return keyArray

def debug_extractKeyPaths (object, keyArray=[], path='', iteration=1):
    '''
    Notes:
    For the record, the line keyArray = getKey(...) originally was just getKey(...), and it also worked
    Despite it seeming like the result of the recursion is thrown out, python must be storing it globally 
    somehow and still referencing the variable. As that seems dangerous, I replaced it with a keyArray=...
    '''
    assert type(object) is dict

    print("\n\nITERATION ", iteration)
    for key in object.keys():
        print("iteration ", iteration, ":  ","evaluating key: ", key, " on path ", path)
        if type(object[key]) is dict: 
            print("iteration ", iteration, ":  ",key, " is a dict" )
            keyArray = debug_extractKeyPaths(object[key], keyArray, path+str(key)+".", iteration=iteration+1)
        elif type(object[key]) is list:
            print("iteration ", iteration, ":  ",key, " is a list" )
            for count, item in enumerate(object[key]):
                if type(item) is str: 
                    keyArray.append(((path + key + "." + str(count)).replace(' ', '_'), cleanDatatypes(type(item).__name__)))
                if type(item) is dict:
                    keyArray = debug_extractKeyPaths(item, keyArray, path + str(key) + ".*.", iteration=iteration+1)
        else:
            print("iteration ", iteration, ":  ",key, " is ", str(type(object[key])))
            keyArray.append(((path + key).replace(' ', '_'), cleanDatatypes(type(object[key]).__name__)))
    print("\n\n")
    return keyArray


'''
Abstract  : Takes list of tuples representing a data type, and formats it into an output blocks expected by appname.json
Input     : A list of tuples in the form (path, value)
Output    : A list of formatted json blocks in the form:

            "data_path"     : data_path,
            "data_type"     : data_type,
            "column_name"   : column_name,
            "column_order"  : column_order
'''
def create_output(array):
    output = []
    # Partially format the information into the blocks appname.json expects
    for count, tuple in enumerate(array):
        path, value = tuple
        output.append({
            "data_path" : "action_result.data.*.{path}".format(path = path),
            "data_type" : value,
            "column_name": path,
            "column_order": count
        })
    # Get the print output so we can modify the default quotes used
    buffer = StringIO()
    sys.stdout = buffer
    pprint(output, sort_dicts=False)
    print_output = buffer.getvalue()
    sys.stdout = sys.__stdout__
    # Using print_output value above, format the text and return
    return print_output.replace("'", '"')


exampleReturn = {
    'Distribution': {
        'Id': 'string',
        'ARN': 'string',
        'Status': 'string',
        'LastModifiedTime': datetime(2015, 1, 1),
        'InProgressInvalidationBatches': 123,
        'DomainName': 'string',
        'ActiveTrustedSigners': {
            'Enabled': True ,
            'Quantity': 123,
            'Items': [
                {
                    'AwsAccountNumber': 'string',
                    'KeyPairIds': {
                        'Quantity': 123,
                        'Items': [
                            'string',
                        ]
                    }
                },
            ]
        },
        'ActiveTrustedKeyGroups': {
            'Enabled': True ,
            'Quantity': 123,
            'Items': [
                {
                    'KeyGroupId': 'string',
                    'KeyPairIds': {
                        'Quantity': 123,
                        'Items': [
                            'string',
                        ]
                    }
                },
            ]
        },
        'DistributionConfig': {
            'CallerReference': 'string',
            'Aliases': {
                'Quantity': 123,
                'Items': [
                    'string',
                ]
            },
            'DefaultRootObject': 'string',
            'Origins': {
                'Quantity': 123,
                'Items': [
                    {
                        'Id': 'string',
                        'DomainName': 'string',
                        'OriginPath': 'string',
                        'CustomHeaders': {
                            'Quantity': 123,
                            'Items': [
                                {
                                    'HeaderName': 'string',
                                    'HeaderValue': 'string'
                                },
                            ]
                        },
                        'S3OriginConfig': {
                            'OriginAccessIdentity': 'string'
                        },
                        'CustomOriginConfig': {
                            'HTTPPort': 123,
                            'HTTPSPort': 123,
                            'OriginProtocolPolicy': 'http-only match-viewer https-only',
                            'OriginSslProtocols': {
                                'Quantity': 123,
                                'Items': [
                                    'SSLv3 TLSv1 TLSv1.1 TLSv1.2',
                                ]
                            },
                            'OriginReadTimeout': 123,
                            'OriginKeepaliveTimeout': 123
                        },
                        'ConnectionAttempts': 123,
                        'ConnectionTimeout': 123,
                        'OriginShield': {
                            'Enabled': True ,
                            'OriginShieldRegion': 'string'
                        },
                        'OriginAccessControlId': 'string'
                    },
                ]
            },
            'OriginGroups': {
                'Quantity': 123,
                'Items': [
                    {
                        'Id': 'string',
                        'FailoverCriteria': {
                            'StatusCodes': {
                                'Quantity': 123,
                                'Items': [
                                    123,
                                ]
                            }
                        },
                        'Members': {
                            'Quantity': 123,
                            'Items': [
                                {
                                    'OriginId': 'string'
                                },
                            ]
                        }
                    },
                ]
            },
            'DefaultCacheBehavior': {
                'TargetOriginId': 'string',
                'TrustedSigners': {
                    'Enabled': True ,
                    'Quantity': 123,
                    'Items': [
                        'string',
                    ]
                },
                'TrustedKeyGroups': {
                    'Enabled': True ,
                    'Quantity': 123,
                    'Items': [
                        'string',
                    ]
                },
                'ViewerProtocolPolicy': 'allow-all https-only redirect-to-https',
                'AllowedMethods': {
                    'Quantity': 123,
                    'Items': [
                        'GET HEAD POST PUT PATCH OPTIONS DELETE',
                    ],
                    'CachedMethods': {
                        'Quantity': 123,
                        'Items': [
                            'GET HEAD POST PUT PATCH OPTIONS DELETE',
                        ]
                    }
                },
                'SmoothStreaming': True ,
                'Compress': True ,
                'LambdaFunctionAssociations': {
                    'Quantity': 123,
                    'Items': [
                        {
                            'LambdaFunctionARN': 'string',
                            'EventType': 'viewer-request viewer-response origin-request origin-response',
                            'IncludeBody': True 
                        },
                    ]
                },
                'FunctionAssociations': {
                    'Quantity': 123,
                    'Items': [
                        {
                            'FunctionARN': 'string',
                            'EventType': 'viewer-request viewer-response origin-request origin-response'
                        },
                    ]
                },
                'FieldLevelEncryptionId': 'string',
                'RealtimeLogConfigArn': 'string',
                'CachePolicyId': 'string',
                'OriginRequestPolicyId': 'string',
                'ResponseHeadersPolicyId': 'string',
                'ForwardedValues': {
                    'QueryString': True ,
                    'Cookies': {
                        'Forward': 'none whitelist all',
                        'WhitelistedNames': {
                            'Quantity': 123,
                            'Items': [
                                'string',
                            ]
                        }
                    },
                    'Headers': {
                        'Quantity': 123,
                        'Items': [
                            'string',
                        ]
                    },
                    'QueryStringCacheKeys': {
                        'Quantity': 123,
                        'Items': [
                            'string',
                        ]
                    }
                },
                'MinTTL': 123,
                'DefaultTTL': 123,
                'MaxTTL': 123
            },
            'CacheBehaviors': {
                'Quantity': 123,
                'Items': [
                    {
                        'PathPattern': 'string',
                        'TargetOriginId': 'string',
                        'TrustedSigners': {
                            'Enabled': True ,
                            'Quantity': 123,
                            'Items': [
                                'string',
                            ]
                        },
                        'TrustedKeyGroups': {
                            'Enabled': True ,
                            'Quantity': 123,
                            'Items': [
                                'string',
                            ]
                        },
                        'ViewerProtocolPolicy': 'allow-all https-only redirect-to-https',
                        'AllowedMethods': {
                            'Quantity': 123,
                            'Items': [
                                'GET HEAD POST PUT PATCH OPTIONS DELETE',
                            ],
                            'CachedMethods': {
                                'Quantity': 123,
                                'Items': [
                                    'GET HEAD POST PUT PATCH OPTIONS DELETE',
                                ]
                            }
                        },
                        'SmoothStreaming': True ,
                        'Compress': True ,
                        'LambdaFunctionAssociations': {
                            'Quantity': 123,
                            'Items': [
                                {
                                    'LambdaFunctionARN': 'string',
                                    'EventType': 'viewer-request viewer-response origin-request origin-response',
                                    'IncludeBody': True 
                                },
                            ]
                        },
                        'FunctionAssociations': {
                            'Quantity': 123,
                            'Items': [
                                {
                                    'FunctionARN': 'string',
                                    'EventType': 'viewer-request viewer-response origin-request origin-response'
                                },
                            ]
                        },
                        'FieldLevelEncryptionId': 'string',
                        'RealtimeLogConfigArn': 'string',
                        'CachePolicyId': 'string',
                        'OriginRequestPolicyId': 'string',
                        'ResponseHeadersPolicyId': 'string',
                        'ForwardedValues': {
                            'QueryString': True ,
                            'Cookies': {
                                'Forward': 'none whitelist all',
                                'WhitelistedNames': {
                                    'Quantity': 123,
                                    'Items': [
                                        'string',
                                    ]
                                }
                            },
                            'Headers': {
                                'Quantity': 123,
                                'Items': [
                                    'string',
                                ]
                            },
                            'QueryStringCacheKeys': {
                                'Quantity': 123,
                                'Items': [
                                    'string',
                                ]
                            }
                        },
                        'MinTTL': 123,
                        'DefaultTTL': 123,
                        'MaxTTL': 123
                    },
                ]
            },
            'CustomErrorResponses': {
                'Quantity': 123,
                'Items': [
                    {
                        'ErrorCode': 123,
                        'ResponsePagePath': 'string',
                        'ResponseCode': 'string',
                        'ErrorCachingMinTTL': 123
                    },
                ]
            },
            'Comment': 'string',
            'Logging': {
                'Enabled': True ,
                'IncludeCookies': True ,
                'Bucket': 'string',
                'Prefix': 'string'
            },
            'PriceClass': 'PriceClass_100 PriceClass_200 PriceClass_All',
            'Enabled': True ,
            'ViewerCertificate': {
                'CloudFrontDefaultCertificate': True ,
                'IAMCertificateId': 'string',
                'ACMCertificateArn': 'string',
                'SSLSupportMethod': 'sni-only vip static-ip',
                'MinimumProtocolVersion': 'SSLv3 TLSv1 TLSv1_2016 TLSv1.1_2016 TLSv1.2_2018 TLSv1.2_2019 TLSv1.2_2021',
                'Certificate': 'string',
                'CertificateSource': 'cloudfront iam acm'
            },
            'Restrictions': {
                'GeoRestriction': {
                    'RestrictionType': 'blacklist whitelist none',
                    'Quantity': 123,
                    'Items': [
                        'string',
                    ]
                }
            },
            'WebACLId': 'string',
            'HttpVersion': 'http1.1 http2 http3 http2and3',
            'IsIPV6Enabled': True ,
            'ContinuousDeploymentPolicyId': 'string',
            'Staging': True 
        },
        'AliasICPRecordals': [
            {
                'CNAME': 'string',
                'ICPRecordalStatus': 'APPROVED SUSPENDED PENDING'
            },
        ]
    },
    'ETag': 'string'
}

keyray = extractKeyPaths(exampleReturn)
print(create_output(keyray))

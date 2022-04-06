# Dynatrace spring4shell exporter
This is a simple python script that exports all processes that have been found to have the spring4shell (CVE-2022-22965) vulnerability via the Dynatrace API. The result is stored in a CSV file

## Prerequisits
- Python 3
- [requests](https://pypi.org/project/requests/) libraries
  - pip install requests
- Dynatrace API Token with Read Entities (`entities.read`) and Read Security Problems (`securityProblems.read`)

#### Arguments
```
-e ENVIRONMENT, --env ENVIRONMENT   The Dynatrace Environment to use (e.g. https://xxxyyyyy.live.dynatrace.com)                    
-t TOKEN, --token TOKEN             The Dynatrace API Token to use (e.g. dt0c01.XXX...)                  
-f, --filters                       Filters for processes with Java 9+ and Tomcat 9+
```

#### Examples
```bash
python3 spring4shell-export.py -e https://xxxyyyyy.live.dynatrace.com -t dt0c01.XXX... 
```
Or to export only processes with Java 9+ and Tomcat
```bash
python3 spring4shell-export.py -e https://xxxyyyyy.live.dynatrace.com -t dt0c01.XXX... -f
```

## Logging
Logs are written to `output.log`, by default the log level is set to INFO, but it can be [changed to DEBUG](#set-log-level-to-debug)

## Additional parameters

### Skip SSL certificate validation
If your environment doesn't have a valid SSL certificate, you can skip the certificate validation with the following flag
> I am not going to lecture you on the importance of using SSL certificates here, you know the drill. 
```
-k , --insecure   Skip SSL certificate validation       
```

### Set log level to DEBUG
By default the log level is set to INFO, it can be changed to debug with the following flag:
> On DEBUG, the full response for each request is logged.
```
--debug   Sets the log level to debug
```

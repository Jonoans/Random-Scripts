@echo off
SETLOCAL EnableDelayedExpansion EnableExtensions

REM ### Basic Configurations ###
SET UserCSVFile=users.csv
SET Domain=acme.local
SET OUInput=Test OU
SET Password=pa$$w0rd

REM ### Advanced Configurations ###
SET UserAddOptions=-disabled no -canchpwd no -pwdneverexpires yes -acctexpires never

REM ### DO NOT MODIFY BEYOND THIS LINE ###

REM # MAIN #

SET Domain=DC=!Domain:.=,DC=!
SET OU=""

IF DEFINED OUInput (
	:ContCreateOU
	CALL :SplitByDelim "!OUInput!", ",", left, right
	CALL :StripString "!left!", left
	CALL :StripString "!right!", right
	SET OUInput=!right!
	IF NOT !OU! == "" (SET OU=OU=!left!,!OU!) ELSE (SET OU=OU=!left!)
	dsadd ou "!OU!,!Domain!" > NUL 2>&1
	IF !ERRORLEVEL! EQU 0 (
		ECHO Created OU "!OU!"
	) ELSE (
		ECHO Failed to create OU "!OU!"
	)
	IF !right! == "" (ECHO. & GOTO :EndCreateOU) ELSE (GOTO :ContCreateOU)
)

:EndCreateOU

ECHO Creating users with password "!Password!"...

FOR /F "skip=1 tokens=1-2 usebackq delims=," %%A IN ("!UserCSVFile!") DO (
	SET Username=%%~A
	SET FullName=%%~B

	CALL :StripString "!Username!", Username
	CALL :StripString "!FullName!", FullName

	IF DEFINED OUInput (
		dsadd user "CN=!FullName!,!OU!,!Domain!" ^
		-samid !Username! -pwd "!Password!" ^
		!UserAddOptions! ^
		> NUL 2>&1
	) ELSE (
		dsadd user "CN=!FullName!,CN=Users,!Domain!" ^
		-samid !Username! -pwd "!Password!" ^
		!UserAddOptions! ^
		> NUL 2>&1
	)

	IF !ERRORLEVEL! EQU 0 (
		ECHO Added User "!Username!" ^(!FullName!^)
	) ELSE (
		ECHO Failed to add User "!Username!"...
	)
)

REM # END MAIN #

ECHO.
ECHO [ ... ENDED ... ]
PAUSE
EXIT /B 0

REM # FUNCTION DEFINITIONS #

REM StripString str, retstr
:StripString
FOR /F "tokens=* delims= " %%A IN ("%~1") DO SET %~2=%%A
FOR /L %%A IN (1,1,100) DO IF "!%~2:~-1!"==" " SET %~2=!%~2:~0,-1!
GOTO :EOF

REM SplitByDelim string string(delim, 1 char) retint
:SplitByDelim
SET ARG0=%~1
SET currPos=0
:SplitByDelimLoop
SET /A currPos+=1
IF "!ARG0:~%currPos%,1!"=="" SET %3=!ARG0! & SET %4="" & GOTO :EOF
IF NOT "!ARG0:~%currPos%,1!"==%2 GOTO :SplitByDelimLoop
SET /A RightPos=%currPos%+1
SET %3=!ARG0:~0,%currPos%! & SET %4=!ARG0:~%RightPos%!
GOTO :EOF
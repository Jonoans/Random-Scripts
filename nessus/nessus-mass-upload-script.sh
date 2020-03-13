#!/bin/bash
# Check if jq is installed
if ! hash jq &> /dev/null; then
	echo "Please install jq before using the script"
	exit 1
fi

url=https://localhost:8834
username=XXX
password=XXX
apiToken=XXX

echo "Authenticating..."
token=$(curl -sk -H "Content-Type: application/json" -X POST "$url/session" --data "{\"username\": \"$username\", \"password\": \"$password\"" | jq .token)
token=$(echo $token | sed --expression='s/"//g')
cookie="X-Cookie: token=$token"
apiToken="X-API-Token: $apiToken"

echo "Getting folders..."
folders=$(curl -sk "$url/folders" -H "Content-Type: application/json" -H "$cookie" -H "$apiToken")
for folder in $(echo $folders | jq -r ".folders[] | @base64"); do
	__decode () {
		echo $folder | base64 -d | jq -r $1
	}
	echo "$(__decode '.id'): $(__decode '.name')"
done
read -p "Please enter the ID of the folder to upload results to: " folderID

files=$(ls -al *.nessus | awk '{ printf "%s\n", $9 }')
while IFS= read -r file; do
	echo "Uploading $file..."
	filename=$(curl -sk -H "$cookie" -X POST "$url/file/upload" -F "Filedata=@$file" | jq .fileuploaded)
	filename=$(echo $filename | sed --expression='s/"//g')
	importOutput=$(curl -sk -X POST "$url/scans/import" -H "Content-Type: application/json" -H "$cookie" -H "$apiToken" --data "{\"file\": \"$filename\", \"folder_id\": \"$folderID\"}")
	echo $importOutput | grep -q "error" && echo "Failed to import $file" || echo "Successfully imported $file"
done <<< "$files"

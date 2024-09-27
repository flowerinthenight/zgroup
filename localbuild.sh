# NOTE: This is specific to my local dev environment.
#
# Usage: ./localbuild.sh {tag}, e.g. ./localbuild.sh v7
#
kubectl delete -f deployment.yaml
docker build --rm -t zgroup .
docker tag zgroup asia.gcr.io/mobingi-main/zgroup:$1
docker push asia.gcr.io/mobingi-main/zgroup:$1
docker rmi $(docker images --filter "dangling=true" -q --no-trunc) -f
sed -i -e 's/image\:\ asia.gcr.io\/mobingi\-main\/zgroup[\:@].*$/image\:\ asia.gcr.io\/mobingi\-main\/zgroup\:'$1'/g' deployment.yaml

default: crds/all.yaml

crds/all.yaml:
	cd helm && helm dep up && \
	  helm template . | yq ea 'select(.kind == "CustomResourceDefinition")' > all.yaml
	mv helm/all.yaml ./crds/.

clean:
	rm -rf helm/charts/
	rm crds/all.yaml

recreate: clean
recreate: crds/all.yaml

rc: recreate

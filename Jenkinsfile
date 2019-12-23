podTemplate(
          label: 'mypod', 
          inheritFrom: 'default',
          containers: [
              containerTemplate(
                  name: 'docker', 
                  image: 'docker:18.02',
                  ttyEnabled: true,
                  command: 'cat'
              ),
              containerTemplate(
                  name: 'kubectl', 
                  image: 'lachlanevenson/k8s-kubectl:v1.8.8',
                  ttyEnabled: true,
                  command: 'cat'
              )
          ],
          volumes: [
              hostPathVolume(
                  hostPath: '/var/run/docker.sock',
                  mountPath: '/var/run/docker.sock'
              )
          ]
      ) {
          node('mypod') {
              def commitId
              def repository
              environment{
                registry_backend = 'registry_backend'
                un_github = 'un_github'
                un_dockerhub = 'un_dockerhub'
                branch_github = 'branch_github'
              }
              
              
              stage ('Extract') {
                  git branch: branch_github, credentialsId: 'github', url: 'https://github.com/'+un_github+'/f19-t2-webapp-backend.git'
                  commitId = sh(script: 'git rev-parse --short HEAD', returnStdout: true).trim()
              }
              
              
              
              stage ('Docker Build') {
                  container('docker'){
                      dockerImage = docker.build registry_backend + ":${commitId}"
                  }
              }
              stage ('Docker Push') {
                  container('docker'){
                      docker.withRegistry( '', 'dockerhub' ) {
                          dockerImage.push()
                      }
                  }
              }
              
              stage ('Deploy application') {
                  container('kubectl'){
                      sh "kubectl set image deployment/backend backend-app=${registry_backend}:${commitId} --record --namespace=api"
                  }
              }
          }
      }
pipeline {
    agent {
        docker {
            image 'firoorg/firo-builder-depends:latest'
            alwaysPull true
        }
    }
    environment {
        CCACHE_DIR = '/tmp/.ccache'
    }
    stages {
        stage('Build dependencies') {
            steps {
                sh 'git clean -d -f -f -q -x'
                dir('depends') {
                    sh 'make -j`nproc` HOST=x86_64-linux-gnu'
                }
            }
        }
        stage('Build') {
            steps {
                sh './autogen.sh'
                sh './configure --prefix=`pwd`/depends/x86_64-linux-gnu'
                sh 'make dist'
                sh 'mkdir -p dist'
                sh 'tar -C dist --strip-components=1 -xzf firo-*.tar.gz'
                dir('dist') {
                    sh './configure --prefix=`pwd`/../depends/x86_64-linux-gnu --enable-elysium --enable-tests --enable-crash-hooks'
                    sh 'make -j`nproc`'
                }
            }
        }
        stage('Test') {
            steps {
                catchError(buildResult: 'FAILURE', stageResult: 'FAILURE'){
                    dir('dist') {
                        sh 'make check'
                    }
                }
            }
        }
        stage('Archive unit tests logs') {
            steps {
                archiveArtifacts artifacts: 'dist/src/test-suite.log',
                allowEmptyArchive: true
                }
        }
        stage('RPC Tests') {
            steps {
                dir('dist') {
                    sh 'qa/pull-tester/rpc-tests.py -extended'
                }
            }
        }
    }
}

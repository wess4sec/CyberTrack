pipeline {
    agent any

    stages {
        stage('1. Checkout GitHub') {
            steps {
                echo 'Recuperation du code source CyberTrack'
                checkout scm
            }
        }

        stage('2. Backend (CI)') {
            steps {
                dir('server') {
                    bat 'npm ci'
                    bat 'npm test'
                    bat 'npm run db:verify'
                }
            }
        }

        stage('3. Frontend (CI)') {
            steps {
                dir('client') {
                    bat 'npm ci'
                    bat 'npm test'
                    bat 'npm run lint'
                    bat 'npm run build'
                }
            }
        }
    }

    post {
        success {
            echo 'CyberTrack CI : tous les controles ont reussi.'
        }
        failure {
            echo 'CyberTrack CI : echec. Consulter la console Jenkins.'
        }
    }
}

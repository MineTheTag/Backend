#!/bin/bash
curl -H "Content-Type: application/json" -X POST -d '{ "username" : "test", "password" : "test" }' http://127.0.0.1:5000/api/user/registration
curl -u test:test -H "Content-Type: application/json" -X POST -d '{ "x_pos" : 41.3885942, "y_pos" : 2.1133071, "tag_id" : 36112568387785220}' http://127.0.0.1:5000/api/tags/new

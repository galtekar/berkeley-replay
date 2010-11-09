load data infile row_key_column=UserID "query-log.tsv" into table 'query-log';
select * from "query-log";
quit

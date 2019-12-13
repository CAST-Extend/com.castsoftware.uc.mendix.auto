create or replace function SET_MENDIX_OMNEXT_2103000  (I_SET_ID int)
returns int
as
$body$
declare
ERRORCODE	INT := 0;
begin
/* 
Set name SET_MENDIX_OMNEXT_2103000

*/ 
  insert into SET_Contents (SetId, ObjectId)
   select distinct I_SET_ID, o.OBJECT_ID
  from CTT_OBJECT_APPLICATIONS o where o.OBJECT_TYPE in 
  		(select IdTyp from TypCat where IdCatParent in                   
  				(select IdCat from Cat where CatNam = 'Mendix_CustomMetrics'));
  
return ERRORCODE;
end;
$body$
LANGUAGE plpgsql
/




